#!/usr/bin/env python3
"""run_syslog_relay.py — NetDoc Syslog Relay (host-side)

Problem: Docker Desktop on Windows NATs all incoming connections to 172.18.0.1,
so rsyslog inside Docker never sees the real device IP.  Every syslog entry
in ClickHouse has src_ip = 172.18.0.1 — device filtering in the UI is broken.

Solution: This relay runs on the Windows HOST (not in Docker), binds to UDP 514
and TCP 514 before Docker sees them, reads the real sender IP from the socket,
replaces the HOSTNAME field in the syslog message with that IP, then forwards
the relayed message to Docker rsyslog on UDP localhost:5140.

rsyslog uses a separate ruleset for port 5140 that maps hostname → src_ip,
so ClickHouse receives the correct device IP in the src_ip column.

Result:
  src_ip   = 192.168.5.1   (real device IP, device filter works)
  hostname = 192.168.5.1   (same — set by relay protocol)
  program  = original program name
  message  = original message body

Port layout:
  HOST UDP 514   → this relay (takes priority over Docker UDP 514 mapping)
  HOST TCP 514   → this relay (takes priority over Docker TCP 514 mapping)
  DOCKER UDP 5140 (localhost only) → rsyslog relay input ← this relay forwards here

Usage:
  python run_syslog_relay.py          # persistent listener
  Task Scheduler: registered by netdoc-setup.ps1 or install_syslog_relay.ps1
"""

import atexit
import datetime
import logging
import os
import re
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "logs" / "syslog_relay.log"
PID_FILE = BASE_DIR / "syslog_relay.pid"

# ── Config ─────────────────────────────────────────────────────────────────────

LISTEN_HOST  = "0.0.0.0"
LISTEN_PORT  = 514           # receive syslog from network devices (UDP + TCP)
FORWARD_HOST = "127.0.0.1"
FORWARD_PORT = 5140          # relay → Docker rsyslog internal port (UDP)
BUFFER_SIZE  = 65535
LOG_INTERVAL = 300           # log stats every 5 min

# ── Syslog message re-crafting ─────────────────────────────────────────────────
#
# The relay replaces the HOSTNAME field in the syslog header with the real
# sender IP address.  Everything else (PRI, timestamp, program, message) is
# kept verbatim.

# RFC 5424:  <PRI>1 TIMESTAMP HOSTNAME rest…
_RFC5424 = re.compile(r'^<(\d{1,3})>1 (\S+) \S+ (.+)$', re.DOTALL)

# RFC 3164:  <PRI>Mmm [d]d hh:mm:ss HOSTNAME rest…
_RFC3164 = re.compile(
    r'^<(\d{1,3})>([A-Za-z]{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+ (.+)$',
    re.DOTALL,
)

# Garbage filter: raw HTTP/RTSP/SIP/nmap traffic misdirected to port 514.
# These arrive when scanners probe port 514 with non-syslog protocols and
# rsyslog/relay parses the method verb as the HOSTNAME field.
_GARBAGE = re.compile(
    r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|'
    r'REGISTER|INVITE|NOTIFY|SUBSCRIBE|REFER|MESSAGE|UPDATE|PRACK|INFO|PUBLISH|'
    r'DIST[0-9])',
    re.IGNORECASE,
)


def _rfc3164_now() -> str:
    return datetime.datetime.utcnow().strftime('%b %d %H:%M:%S')


def make_relay_msg(raw: bytes, real_ip: str) -> bytes | None:
    """Re-craft syslog message with real source IP as HOSTNAME field.

    Returns None for garbage (HTTP/RTSP/nmap) — message is silently dropped.
    """
    text = raw.decode('utf-8', errors='replace').rstrip('\r\n\x00')
    if not text:
        return None

    # RFC 5424
    m = _RFC5424.match(text)
    if m:
        pri, ts, rest = m.groups()
        first = rest.split(None, 1)[0] if rest else ''
        if _GARBAGE.match(first):
            return None
        return f'<{pri}>1 {ts} {real_ip} {rest}\n'.encode('utf-8', errors='replace')

    # RFC 3164
    m = _RFC3164.match(text)
    if m:
        pri, ts, rest = m.groups()
        first = rest.split(None, 1)[0] if rest else ''
        if _GARBAGE.match(first):
            return None
        return f'<{pri}>{ts} {real_ip} {rest}\n'.encode('utf-8', errors='replace')

    # Unknown format — check first word for garbage
    first = text.split(None, 1)[0]
    if _GARBAGE.match(first):
        return None

    # Wrap as minimal RFC 3164
    return f'<14>{_rfc3164_now()} {real_ip} {text}\n'.encode('utf-8', errors='replace')


# ── Stats ──────────────────────────────────────────────────────────────────────

_lock        = threading.Lock()
_forwarded   = 0
_dropped     = 0
_errors      = 0


def _inc(key: str) -> None:
    global _forwarded, _dropped, _errors
    with _lock:
        if key == 'f':
            _forwarded += 1
        elif key == 'd':
            _dropped += 1
        else:
            _errors += 1


# ── Forward socket (UDP, shared across handler threads) ───────────────────────

_fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _forward(msg: bytes, real_ip: str) -> None:
    """Forward a single re-crafted message to Docker rsyslog."""
    try:
        _fwd.sendto(msg, (FORWARD_HOST, FORWARD_PORT))
        _inc('f')
    except OSError as exc:
        logger.warning("forward error from %s: %s", real_ip, exc)
        _inc('e')


# ── UDP handler ────────────────────────────────────────────────────────────────

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, _sock = self.request
        real_ip = self.client_address[0]
        msg = make_relay_msg(data, real_ip)
        if msg is None:
            _inc('d')
            return
        _forward(msg, real_ip)


class _ReuseUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


# ── TCP handler ────────────────────────────────────────────────────────────────
# Syslog over TCP uses octet-counting framing (RFC 6587) or newline-delimited.
# We support both:
#   Octet-counting:  "<length> <syslog-msg>"  e.g. "83 <34>1 2026-..."
#   Non-transparent: messages separated by newline (most common in practice)

class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        real_ip = self.client_address[0]
        buf = b''
        try:
            while True:
                chunk = self.request.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk
                # Process all complete newline-delimited messages in buffer
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    line = line.rstrip(b'\r')
                    if not line:
                        continue
                    # Octet-counting framing: "<digits> <rest>"
                    # Strip the length prefix if present
                    decoded = line.decode('utf-8', errors='replace')
                    space_pos = decoded.find(' ')
                    if space_pos > 0 and decoded[:space_pos].isdigit():
                        line = decoded[space_pos + 1:].encode('utf-8', errors='replace')
                    msg = make_relay_msg(line, real_ip)
                    if msg is None:
                        _inc('d')
                    else:
                        _forward(msg, real_ip)
        except OSError:
            pass  # connection reset / timeout — normal for syslog TCP


class _ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── Logging ────────────────────────────────────────────────────────────────────

def _setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = '%(asctime)s [%(levelname)s] %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(LOG_FILE), encoding='utf-8'),
        ],
    )


logger = logging.getLogger(__name__)


# ── Single-instance lock (PID file) ───────────────────────────────────────────

def _pid_alive(pid: int) -> bool:
    """Returns True if a process with given PID exists.

    Uses psutil for cross-platform correctness — os.kill(pid, 0) on Windows
    sends CTRL_C_EVENT (signal 0) instead of checking process existence,
    which raises SystemError for GUI processes like pythonw.exe.
    """
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError, SystemError):
            return False


def _acquire_relay_lock() -> bool:
    """Ensures only one syslog relay instance runs at a time.

    Returns True if lock acquired, False if another instance is already running.
    """
    my_pid = os.getpid()

    if PID_FILE.exists():
        try:
            old_pid = int(PID_FILE.read_text().strip())
            if old_pid != my_pid and _pid_alive(old_pid):
                logger.error(
                    "Syslog relay already running (PID=%d). Exiting.", old_pid
                )
                return False
            if old_pid != my_pid:
                logger.warning("Stale syslog_relay.pid (PID=%d) — removing.", old_pid)
        except (ValueError, OSError):
            pass  # corrupted file — overwrite
        try:
            PID_FILE.unlink()
        except OSError:
            pass

    # Atomic write — open("x") raises FileExistsError if another instance
    # managed to create the file between our check and this write (TOCTOU guard).
    try:
        with open(str(PID_FILE), "x") as _f:
            _f.write(str(my_pid))
    except FileExistsError:
        try:
            racing_pid = int(PID_FILE.read_text().strip())
            logger.error("Race condition: relay PID=%d got ahead. Exiting.", racing_pid)
        except OSError:
            logger.error("Race condition: another relay instance got ahead. Exiting.")
        return False
    except OSError as exc:
        logger.warning("Cannot write PID file: %s — continuing anyway.", exc)

    atexit.register(_remove_pid)
    return True


def _remove_pid() -> None:
    try:
        if PID_FILE.exists() and PID_FILE.read_text().strip() == str(os.getpid()):
            PID_FILE.unlink()
    except OSError:
        pass


# ── Stats thread ───────────────────────────────────────────────────────────────

def _stats_loop() -> None:
    while True:
        time.sleep(LOG_INTERVAL)
        with _lock:
            f, d, e = _forwarded, _dropped, _errors
        logger.info("stats: forwarded=%d dropped=%d errors=%d", f, d, e)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    _setup_logging()
    if not _acquire_relay_lock():
        sys.exit(0)

    logger.info("NetDoc Syslog Relay starting")
    logger.info("  listen  : UDP %s:%d  (network devices)", LISTEN_HOST, LISTEN_PORT)
    logger.info("  listen  : TCP %s:%d  (network devices)", LISTEN_HOST, LISTEN_PORT)
    logger.info("  forward : UDP %s:%d  (Docker rsyslog relay input)", FORWARD_HOST, FORWARD_PORT)

    threading.Thread(target=_stats_loop, daemon=True).start()

    try:
        udp_srv = _ReuseUDPServer((LISTEN_HOST, LISTEN_PORT), _UDPHandler)
        tcp_srv = _ReuseTCPServer((LISTEN_HOST, LISTEN_PORT), _TCPHandler)
    except PermissionError:
        logger.error(
            "Cannot bind to port %d — run as Administrator "
            "(required for ports < 1024 on Windows).",
            LISTEN_PORT,
        )
        sys.exit(1)

    # Run TCP server in background thread, UDP in main thread
    tcp_thread = threading.Thread(target=tcp_srv.serve_forever, daemon=True)
    tcp_thread.start()
    logger.info("Relay ready — UDP + TCP — real source IPs will be preserved in ClickHouse.")

    try:
        udp_srv.serve_forever()
    except KeyboardInterrupt:
        logger.info("Relay stopped by user.")
    finally:
        udp_srv.shutdown()
        tcp_srv.shutdown()
        _remove_pid()


if __name__ == '__main__':
    main()
