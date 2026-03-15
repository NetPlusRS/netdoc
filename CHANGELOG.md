# Changelog

Format oparty na [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

## [0.1.9] - 2026-03-10

### Added
- Automatyczne wykrywanie nowych sieci przy zmianie interfejsów hosta
- Task Scheduler: brak zatrzymania skanera przy pracy na baterii
- Watchdog pilnujący ciągłości skanowania

### Fixed
- Banner ping-workera: próg ostrzeżenia ustawiony na 2 minuty
- Zakładka Workery Docker w Logach — naprawiony błąd JS

## [0.1.8] - 2026-03-09

### Added
- Nowy typ urządzenia: `workstation` (laptop/PC bez usług serwerowych)
- Klasyfikacja po portach: 135+139 → workstation, 9100/515/631 → printer
- Rozszerzona lista portów: 135, 139, 515, 631, 5353, 623, 16992

### Fixed
- Drukarki HP z portem 9100 poprawnie klasyfikowane jako `printer`
- Reklasyfikacja urządzeń używa rzeczywistych portów (nie pustego zbioru)

## [0.1.7] - 2026-03-08

### Added
- run_scanner.py: tryb `--once` (Task Scheduler co 5 min)
- Single-instance lock (scanner.pid)
- SNMP: daemon thread z timeoutem — fix zawieszania event loop

### Fixed
- `--send-ip` usunięte z ping sweep (powodowało pominięcie hostów na Windows)
- UniFi driver wywoływany tylko dla urządzeń Ubiquiti (nie dla każdego)

## [0.1.6] - 2026-03-07

### Added
- Wykrywanie sieci VPN po nazwie interfejsu (tun*, wg*, ppp*, tap*)
- SCAN_VPN_NETWORKS=true — opcjonalne skanowanie sieci VPN

## [0.1.5] - 2026-03-06

### Added
- GoAhead-Webs support (Cisco SF/SG/CBS) — login przez XML API
- VNC credential testing z poprawną obsługą 8-znakowego limitu hasła
- Credential re-weryfikacja przy każdym cyklu skanowania

### Fixed
- False positive: admin/admin na kamerach przez HTTP (usunięte)
- Unauth reboot check: odrzucanie odpowiedzi HTML/SPA (Ubiquiti UDM Pro)
