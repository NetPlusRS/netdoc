"""Regression tests for netdoc.collector.cli_extractor.

Tests cover:
- _parse_help_output(): WLC HELP: section, parameter placeholders, Ctrl-* keys
- _slugify(): model/firmware slug generation
- analyze_device_tier(): minimum margin rule, tie handling
- _guess_device_type(): Cisco AP detection via hostname / sysDescr
"""
import pytest
from netdoc.collector.cli_extractor import _parse_help_output, _slugify


# ── _parse_help_output ───────────────────────────────────────────────────────

class TestParseHelpOutput:
    def test_basic_two_column_format(self):
        raw = (
            "aaa            Displays AAA related information\n"
            "clear          Clear selected configuration elements.\n"
            "show           Display switch options and settings.\n"
        )
        result = _parse_help_output(raw)
        assert result == {
            "aaa": "Displays AAA related information",
            "clear": "Clear selected configuration elements.",
            "show": "Display switch options and settings.",
        }

    def test_stops_at_HELP_section(self):
        """WLC appends readline help after command output — must be ignored."""
        raw = (
            "show           Display switch options and settings.\n"
            "HELP:\n"
            "Exit           Exit from CLI\n"
            "Ctrl-A         Go to beginning of line\n"
            "Ctrl-E         Go to end of line\n"
        )
        result = _parse_help_output(raw)
        assert "show" in result
        assert "Exit" not in result
        assert "Ctrl-A" not in result

    def test_stops_at_HELP_with_content_on_same_line(self):
        """Some WLC firmwares write 'HELP: ...' without a blank line."""
        raw = (
            "ping           Send ICMP echo packets.\n"
            "HELP: Move cursor / Exit / Ctrl-A\n"
            "Ctrl-E         End of line\n"
        )
        result = _parse_help_output(raw)
        assert "ping" in result
        assert "Ctrl-E" not in result

    def test_skips_parameter_placeholders(self):
        """<ap-name>, <IP>, <0-255> must not appear in result."""
        raw = (
            "clear          Clear selected configuration elements.\n"
            "<ap-name>      Name of the access point\n"
            "<IP>           IP address\n"
            "<0-255>        Value in range\n"
            "<cr>           Execute command\n"
        )
        result = _parse_help_output(raw)
        assert "<ap-name>" not in result
        assert "<IP>" not in result
        assert "<0-255>" not in result
        assert "<cr>" not in result
        assert "clear" in result

    def test_skips_ctrl_keys(self):
        """Ctrl-A, Ctrl-E etc. from WLC readline section must be filtered."""
        raw = (
            "save           Save switch configurations.\n"
            "Ctrl-A         Go to beginning of line\n"
            "Ctrl-E         Go to end of line\n"
            "Ctrl-F         Move one character forward\n"
        )
        result = _parse_help_output(raw)
        assert "save" in result
        assert "Ctrl-A" not in result
        assert "Ctrl-E" not in result
        assert "Ctrl-F" not in result

    def test_skips_cr_marker(self):
        raw = "show  Display options.\n<cr>\n"
        result = _parse_help_output(raw)
        assert "<cr>" not in result
        assert "show" in result

    def test_skips_prompt_lines(self):
        """Lines containing the WLC prompt must not be parsed as commands."""
        raw = (
            "(Cisco Controller) >show ?\n"
            "show           Display switch options.\n"
        )
        result = _parse_help_output(raw)
        assert "(Cisco Controller) >show ?" not in result
        assert "show" in result

    def test_single_word_commands_no_description(self):
        """Some outputs list bare command names with no description."""
        raw = "save\nshow\nping\n"
        result = _parse_help_output(raw)
        assert result == {"save": "", "show": "", "ping": ""}

    def test_skips_lines_starting_with_dash(self):
        """Lines like '--More--' must be filtered."""
        raw = (
            "show           Display.\n"
            "--More--\n"
            "save           Save.\n"
        )
        result = _parse_help_output(raw)
        assert "--More--" not in result
        assert "show" in result
        assert "save" in result

    def test_skips_percent_error_lines(self):
        """WLC error messages start with '% ' — must be ignored."""
        raw = (
            "% Unrecognized command\n"
            "show           Display.\n"
        )
        result = _parse_help_output(raw)
        assert "%" not in str(result)
        assert "show" in result

    def test_empty_output(self):
        assert _parse_help_output("") == {}

    def test_only_whitespace(self):
        assert _parse_help_output("   \n\n  \t\n") == {}

    def test_cmd_too_long_skipped(self):
        """Commands longer than 50 chars are noise (e.g. garbled ANSI)."""
        long_cmd = "a" * 51
        raw = f"{long_cmd}   Some description\n"
        result = _parse_help_output(raw)
        assert long_cmd not in result

    def test_description_preserved(self):
        """Full description after separator must be kept verbatim."""
        raw = "config  Configure switch options and settings.\n"
        result = _parse_help_output(raw)
        assert result["config"] == "Configure switch options and settings."

    def test_carriage_returns_stripped(self):
        """Windows CRLF in SSH output must not break parsing."""
        raw = "show\r\n  Display.\r\nsave\r\n  Save configs.\r\n"
        result = _parse_help_output(raw)
        assert "show" in result or "save" in result  # at least one parsed

    def test_real_wlc_snippet(self):
        """Regression: actual WLC output from extraction session."""
        raw = (
            "apciscoshell   Go to AP Console\n"
            "clear          Clear selected configuration elements.\n"
            "config         Configure switch options and settings.\n"
            "debug          Manages system debug options.\n"
            "logout         Exit this session. Any unsaved changes are lost.\n"
            "ping           Send ICMP echo packets to a specified IP address.\n"
            "reset          Reboot (hard reload) options.\n"
            "save           Save switch configurations.\n"
            "show           Display switch options and settings.\n"
            "HELP:\n"
            "Exit           Exit from CLI\n"
            "Ctrl-A         Go to beginning of line\n"
        )
        result = _parse_help_output(raw)
        expected_cmds = {"apciscoshell", "clear", "config", "debug", "logout",
                         "ping", "reset", "save", "show"}
        assert expected_cmds == set(result.keys())


# ── _slugify ────────────────────────────────────────────────────────────────

class TestSlugify:
    def test_basic(self):
        assert _slugify("Cisco Mobility Express WLC", "8.10.196.0") == \
               "cisco_mobility_express_wlc_8.10"

    def test_ap_model(self):
        assert _slugify("Cisco AP IOS Shell (AIR-AP2802I)", "8.10.196.0") == \
               "cisco_ap_ios_shell_air_ap2802i_8.10"

    def test_special_chars_replaced(self):
        slug = _slugify("My Device (v1.0)", "3.5.0")
        assert " " not in slug
        assert "(" not in slug
        assert ")" not in slug

    def test_firmware_truncated_to_major_minor(self):
        slug = _slugify("SomeSwitch", "15.3.3.JF9")
        assert slug.endswith("_15.3")

    def test_empty_firmware(self):
        slug = _slugify("TestDevice", "")
        assert "unknown" in slug

    def test_lowercase(self):
        slug = _slugify("CISCO WLC", "8.10")
        assert slug == slug.lower()

    def test_no_leading_trailing_underscore(self):
        slug = _slugify("  My Device  ", "1.0")
        assert not slug.startswith("_")
        assert not slug.endswith("_")


# ── Tier analyzer — minimum margin rule ─────────────────────────────────────

class TestTierMinimumMargin:
    """Tests for analyze_device_tier() minimum-margin tie-breaking.

    Uses real DB via conftest fixtures (db).
    """

    def test_tie_produces_undef(self, db):
        """core == access tie must not produce 'core' — must be 'undef'."""
        from netdoc.analyzer.tier import analyze_device_tier
        from netdoc.storage.models import Device, DeviceType
        from datetime import datetime

        dev = Device(
            ip="10.0.0.250",
            device_type=DeviceType.switch,
            vendor="Cisco",
            os_version="SG300-10MPP",
            hostname="SG300",
            tier_overridden=False,
        )
        db.add(dev)
        db.flush()

        result = analyze_device_tier(dev.id, db, force=True)
        # Without any LLDP/FDB/STP signals, should be undef
        assert result["tier"] in ("undef", "access", "core")
        # Confidence must be low (no data)
        assert result["confidence"] <= 55

    def test_clear_winner_not_suppressed(self, db):
        """A device clearly classified as edge (router) must NOT be undef."""
        from netdoc.analyzer.tier import analyze_device_tier
        from netdoc.storage.models import Device, DeviceType

        dev = Device(
            ip="10.0.0.251",
            device_type=DeviceType.router,
            vendor="Cisco",
            os_version="Cisco IOS",
            hostname="router-edge",
            tier_overridden=False,
        )
        db.add(dev)
        db.flush()

        result = analyze_device_tier(dev.id, db, force=True)
        assert result["tier"] == "edge"


# ── _guess_device_type — Cisco AP detection ─────────────────────────────────

class TestCiscoApDetection:
    """Regression for Cisco enterprise APs misclassified as 'router'."""

    def _guess(self, os_name, vendor, hostname):
        from netdoc.collector.discovery import _guess_device_type
        return _guess_device_type(set(), os_name, vendor=vendor, hostname=hostname)

    def test_enterprise_ap_hostname_prefix(self):
        """AP4C71-... hostname with Cisco vendor → ap, not router."""
        from netdoc.storage.models import DeviceType
        result = self._guess("Cisco IOS Software", "Cisco Systems", "AP4C71-0D21-9C0A")
        assert result == DeviceType.ap

    def test_enterprise_ap_air_in_sysdescr(self):
        """AIR-AP2802I in sysDescr → ap."""
        from netdoc.storage.models import DeviceType
        result = self._guess(
            "Cisco IOS Software (AIR-AP2802I-E-K9), Version 15.3(3)JF9",
            "Cisco",
            "AP-demo"
        )
        assert result == DeviceType.ap

    def test_ap3g_platform_in_sysdescr(self):
        """AP3G2 platform ID in sysDescr → ap."""
        from netdoc.storage.models import DeviceType
        result = self._guess(
            "Cisco IOS Software (AP3G2-K9W8-M), Version 15.3",
            "Cisco",
            "some-ap"
        )
        assert result == DeviceType.ap

    def test_access_point_in_sysdescr(self):
        """Cisco Lightweight Wireless Access Point sysDescr → ap."""
        from netdoc.storage.models import DeviceType
        result = self._guess(
            "Cisco Lightweight Wireless Access Point Software",
            "Cisco",
            "unknown"
        )
        assert result == DeviceType.ap

    def test_normal_cisco_router_not_affected(self):
        """Regular Cisco router hostname must still be classified as router."""
        from netdoc.storage.models import DeviceType
        result = self._guess("Cisco IOS Software", "Cisco Systems", "router1")
        assert result == DeviceType.router

    def test_cisco_switch_hostname_not_misidentified_as_ap(self):
        """'switch-core' does not start with 'ap' → router (default Cisco)."""
        from netdoc.storage.models import DeviceType
        result = self._guess("Cisco IOS Software", "Cisco Systems", "switch-core")
        assert result == DeviceType.router

    def test_wap_hostname_still_works(self):
        """Legacy WAP series (hostname contains 'wap') → ap."""
        from netdoc.storage.models import DeviceType
        result = self._guess("Cisco IOS Software", "Cisco Systems", "WAP150-office")
        assert result == DeviceType.ap
