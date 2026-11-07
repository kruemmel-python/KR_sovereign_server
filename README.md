# Sovereign Server V10 Professional - KR Unified Language Edition

Vollständige Neuentwicklung und Transformation des **Sovereign Server V9/V10** in die **KR Unified Language (`.kr`)** mit nativer Multi-Sprachen-Fusion: **C++20, Rust und Go** in einem gemeinsamen Compiler-Projekt.

---

## 1. Sprachen-Architektur & Rollenverteilung

Das Projekt nutzt die spezifischen Stärken aller drei Sprachen ohne künstliche Wrapper oder Decorators:

| Sprache | Modul / Rolle | Implementierte Kern-Komponenten |
|---|---|---|
| **C++20** | `network/network_mod.kr`, `php/php_mod.kr`, `main.kr` | WinSock2, begrenzter Worker-Pool, HTTP-Routing, statische Dateien und isoliertes PHP-CGI-Gateway, Response-Serialisierung und Einstiegspunkt. |
| **Rust** | `protocol/protocol_mod.kr`, `security/security_mod.kr` | Zero-Panic HTTP/1.1 Request-Parser, CR/LF-Injection-Filter, Path-Traversal-Sanitizer, RFC 3174 SHA-1 & RFC 6455 WebSocket Handshake & Framer, FIPS 180-4 SHA-256 Digest-Engine, RFC 2104 HMAC-SHA256, Constant-Time Compare, Kryptographisches JWT-Signieren/Verifizieren, Token-Bucket Rate-Limiter. |
| **Go** | `orchestration/orchestration_mod.kr`, `security/security_mod.kr` | Bounded Admission-Control Semaphore (Kanal-basiert), Persistente Background-Task-Queue mit asynchronem Worker-Goroutinen-Pool, EventHub Pub/Sub-Message-Broker, Latenz- und Request-Metriken Profiler, Sandbox Environment Security Auditing. |

---

## 2. Projektstruktur

```text
KR_sovereign_server/
├── sovereign_server.krproject      # KR Project Manifest (Target: WINDOWS)
├── main.kr                         # Root Coordinator & CLI Test-Suite
├── network/
│   └── network_mod.kr              # C++20 WinSock2 HTTP & WebSocket Server
├── protocol/
│   └── protocol_mod.kr             # Rust HTTP Request Parser & RFC 6455 WebSocket Framing
├── security/
│   └── security_mod.kr             # Rust SHA-256, HMAC, JWT, Rate Limiter & Go Sandbox Audit
├── orchestration/
│   └── orchestration_mod.kr        # Go Admission, Worker-Goroutinen, EventHub & Metrics
├── php/php_mod.kr                  # Optionales, begrenztes PHP-CGI-/CMS-Gateway
├── www/                            # Dokumentwurzel fuer CMS und statische Dateien
├── stack/                          # Module, Pakete, Daten, Logs, Temp und Konfiguration
├── SovereignStackManager.ps1       # Lokales WPF Control Center
└── KR_BUILD/                       # Build-Verzeichnis & Compiler-Artefakte
    ├── kr-sovereign-server-*.exe   # Kompiliertes natives Windows-Executable
    ├── kr_bridge.h                 # Vom KR Compiler generierter C-ABI Header
    ├── rust_module/                # Vom KR Compiler erzeugte Rust-Crate (libkr_rust.a)
    └── go_module/                  # Vom KR Compiler erzeugtes Go C-Archive (libkr_go.a)
```

---

## 3. Validierung & Kompilierung

### A. Syntax- & FFI-Check
```bash
python C:\Users\ralfk\.gemini\config\plugins\kr-compile\skills\kr-compile\scripts\kr_tool.py check KR_sovereign_server
```

### B. Kompilierung für Windows x64
```bash
python C:\Users\ralfk\.gemini\config\plugins\kr-compile\skills\kr-compile\scripts\kr_tool.py build KR_sovereign_server --target WINDOWS
```

---

## 4. Ausführung & Test-Suite

### Automatisierte Multilinguale Test-Suite (`--test`)
Der Server besitzt eine eingebaute 14-Punkte-Test-Suite, die die
sprachübergreifenden Aufrufe, Algorithmen und zentralen Negativfälle verifiziert:

```bash
.\KR_BUILD\kr-sovereign-server-56d51cc8.exe --test
```

**Verifizierte Tests:**
1. **Rust**: HTTP-Header CR/LF Injection Defense
2. **Rust**: Directory Traversal Sanitizer (`../../windows/system32/cmd.exe` wird neutralisiert)
3. **Rust**: Pure SHA-256 FIPS 180-4 Test Vector (`abc` -> `ba7816bf...`)
4. **Rust**: RFC 6455 WebSocket Handshake Vector (`dGhlIHNhbXBsZSBub25jZQ==` -> `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`)
5. **Rust**: JWT HMAC-SHA256 Signieren, Verifizieren und Ablehnung manipulierter Signaturen
6. **Rust**: High-Precision Token-Bucket Rate Limiter
7. **Go**: Concurrency Admission-Control Semaphore
8. **Go**: Background Task Queue & Worker Goroutinen
9. **Go**: EventHub Pub/Sub Broker
10. **Go**: Latenz- & Request-Metriken Profiling
11. **Rust/C++**: Striktes HTTP/1.1-Framing, Host-Pflicht, NUL-, CL/TE-Ablehnung
12. **Rust/C++**: WebSocket-Maskierung, Fragmentierung und Längengrenzen
13. **Rust/C++**: JWT-Ablauf, Pflicht-Claims und Mindestschlüssellänge
14. **Rust**: Fail-closed Rate-Limiter-Parameter

### Security-Integrationstests

Nach jedem neuen Build prüft das PowerShell-5.1-kompatible Integrationsskript
die tatsächliche EXE über lokale TCP-Verbindungen:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\security_integration.ps1
```

Das Skript verwendet zufällige, nur für den Testprozess gesetzte Secrets und
prüft Token-Ausgabe, geschützte Routen, Task-Autorisierung, WebSocket-Upgrade,
HTTP-Framing und die Ablehnung einer Remote-Bindung. Testlogs werden in
`KR_BUILD/security-*.log` geschrieben.

---

## 5. Server-Start & HTTP/WebSocket Endpunkte

Empfohlener lokaler Start nach dem Build ist das modulare Control Center:

```powershell
.\SovereignStackManager.bat
```

Es aktiviert die in `stack/state.json` gewählte PHP-Version, verwaltet MariaDB
auf `127.0.0.1:3308` und hält TEMP/TMP, Logs, Sessions und Daten auf Laufwerk F:.
Der direkte sichere Start bleibt ebenfalls verfügbar:

```powershell
.\start_secure.ps1
```

Alternativ kann `start_secure.bat` per Doppelklick gestartet werden. Fehlen
gueltige Umgebungsvariablen, erzeugt der Starter fuer diese Sitzung zwei
kryptographisch zufaellige, getrennte Geheimnisse. Er zeigt nur das
Bootstrap-Token an; der JWT-Signierschluessel wird nicht ausgegeben. Die Werte
werden nicht persistent gespeichert, daher werden ausgestellte JWTs beim
Neustart ungueltig. Der Starter verweigert eine veraltete EXE.

Fuer einen dauerhaften Betrieb werden die beiden Werte ueber eine sichere
Secret-Verwaltung gesetzt und der Starter danach normal aufgerufen:

```powershell
$env:SOVEREIGN_JWT_SECRET = "<zufaelliges Geheimnis mit mindestens 32 Bytes>"
$env:SOVEREIGN_BOOTSTRAP_TOKEN = "<anderes zufaelliges Geheimnis mit mindestens 32 Bytes>"
.\start_secure.ps1 -Port 8085 -Workers 8
```

Der Server startet fail-closed, wenn eine der beiden Variablen fehlt, zu kurz/zu
lang ist oder beide Werte identisch sind. Er bindet ausschließlich an
`127.0.0.1`. Für Fernzugriff muss ein lokaler TLS-Reverse-Proxy vorgeschaltet
werden; direkte unverschlüsselte Remote-Bindings werden abgelehnt.

### Verfügbare Endpunkte:
- `GET /`: Bei aktivem PHP-Modul die CMS-Dokumentwurzel `www`; andernfalls das
  eingebaute HTML-Dashboard.
- `GET /health`: JSON-Metriken aus Go (`active_connections`, `total_requests`, `average_latency_us`, `background_tasks_processed`).
- `POST /auth/token`: Generiert ein kurzlebiges HMAC-SHA256-JWT; erfordert
  `Authorization: Bearer <SOVEREIGN_BOOTSTRAP_TOKEN>`.
- `GET /api/secure`: Authentifizierter Endpunkt mit Prüfung des `Authorization: Bearer <token>` Headers via Rust.
- `POST /api/tasks`: Reiht authentifiziert Aufgaben in die begrenzte Go-Worker-Queue ein.
- `GET /api/eventhub/stats`: Zeigt EventHub Pub/Sub-Statistiken aus Go.
- `GET /ws`: Authentifizierter RFC-6455-WebSocket-Handshake und begrenzte
  Echo-/Frame-Session; erfordert ebenfalls ein gültiges JWT im Bearer-Header.

---

## 6. Sicherheitsrichtlinien (Sovereign Paranoid)
- Automatische Security-Header auf allen Responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Content-Security-Policy: default-src 'self'`
- CR/LF Injection-Prävention auf allen ausgehenden und eingehenden Headern.
- Die optionale Datei-/PHP-Route dekodiert Pfade strikt, bleibt unter `www`,
  sperrt versteckte und sensible Dateitypen und folgt keinen Reparse-Punkten.
- Token-Bucket-Schutz gegen DoS und Brute-Force.
- Admission-Control direkt nach `accept`; aktive plus wartende Verbindungen
  sind auf die dreifache Workerzahl begrenzt. Überkapazität erreicht die
  Threadpool-Queue nicht.
- Absolute 5-Sekunden-Header- und 60-Sekunden-HTTP-Verbindungsdeadline gegen
  Slowloris-Verbindungen; sicherheitsrelevante Socketoptionen werden geprüft.
- Exklusive Windows-Portbindung mittels `SO_EXCLUSIVEADDRUSE`.
- Auf 16.384 aktive Identitäten begrenzter Token-Bucket-Speicher mit Ablauf
  inaktiver Einträge.
- Striktes HTTP/1.1-Framing: genau eine kanonische `Content-Length` bis 16 MiB
  ist nur für Body-Methoden erlaubt und wird bytegenau gelesen;
  `Transfer-Encoding`, doppelte Längen und überzählige Bytes werden abgelehnt.
- PHP läuft ohne offenen CGI/FastCGI-Port in einem Jobobjekt mit Prozess-,
  Speicher-, Laufzeit- und Ausgabelimits. Die Kindumgebung enthält weder JWT-
  noch Bootstrap-Secret; Dateipfade bleiben in `www` und Reparse-Punkte werden
  abgelehnt. Aktivierung erfolgt ausschließlich explizit über
  `SOVEREIGN_PHP_ENABLED=1`; fehlende oder deaktivierte Module bleiben aus.
- Exakte HTTP/1.1-Request-Line ohne Tabs oder wiederholte Trennzeichen sowie
  kanonische WebSocket-Handshake-Keys.
- Dynamische JSON-Werte werden maskiert; JWT-Claims besitzen eine kanonische,
  eindeutig geprüfte Struktur.
