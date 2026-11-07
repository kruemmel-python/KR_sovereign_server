# Statischer Security-Audit – Sovereign Server mit PHP/MariaDB-Stack

Stand: 7. November 2026. Geprüft wurden alle Quell-, Start-, Test- und
Konfigurationsdateien des Projekts sowie Struktur, Pfade, PE-Architektur und
Hashes der eingebundenen Herstellerarchive. Der Audit war rein statisch:
Server, PHP, MariaDB, Buildskripte und erzeugte Binärdateien wurden von Codex
nicht ausgeführt.

## Ergebnis

Die zuvor bestätigten kritischen und hohen Schwachstellen im Serverkern sind im
Quellstand behoben. Zusätzlich wurde der optionale PHP-/MariaDB-Stack mit
fail-closed Modulaktivierung, begrenztem CGI-Prozessmodell und lokaler
Bedienoberfläche implementiert. Ein abschließendes Sicherheitsurteil für die
neue Version ist erst nach den noch ausstehenden Benutzer-Laufzeittests möglich.

## Behobene bestätigte Befunde

### Kritisch: unauthentifizierte Ausgabe privilegierter JWTs

`POST /auth/token` stellte ursprünglich ohne Identitätsprüfung ein gültiges
Operator-JWT aus. Die Ausgabe erfordert nun einen separaten Bootstrap-Bearer,
der konstantzeitlich verglichen wird. JWT- und Bootstrap-Secret müssen
verschiedene, 32–256 Byte lange Werte sein; der Prozess startet andernfalls
nicht. Task- und WebSocket-Routen prüfen ebenfalls das JWT.

### Hoch: fest einkompilierter JWT-Schlüssel

Der produktive Signierschlüssel wurde aus dem Quellcode entfernt. Er wird nur
aus der Prozessumgebung beziehungsweise im Control Center aus einer
benutzergebundenen Windows-DPAPI-Ablage geladen. PHP erhält eine eigens
aufgebaute Kindumgebung ohne diese beiden Server-Secrets.

### Hoch: WebSocket-Out-of-bounds-Read und unbegrenzte Sitzungen

Der Echo-Pfad vertraute einer deklarierten Payloadlänge, obwohl nicht alle
Bytes empfangen waren. Headergrenze, reale Empfangslänge, Maskierung,
Kontrollframe-Regeln und 4-KiB-Maximum werden jetzt gemeinsam geprüft.
WebSockets benötigen ein JWT, sind auf die halbe Workerzahl begrenzt und enden
nach 60 Sekunden oder 1.000 Frames.

### Hoch: Klartext-Bearer über Remote-Bindung

Da der Prozess kein TLS implementiert, bindet er ausschließlich an
`127.0.0.1`. Externer Zugriff benötigt einen lokalen TLS-Reverse-Proxy. Auch
MariaDB bindet ausschließlich an Loopback, standardmäßig Port 3308. Port 3307
war auf dem Prüfgerät bereits durch eine bestehende MySQL-8.3-Installation
belegt; der Stack verweigert belegte Ports nun vor dem Prozessstart.

### Hoch: unsichere PHP-Dateiauflösung und Secret-Vererbung (bei der neuen Funktion)

Eine naive CGI-Anbindung hätte Traversal, Symlink-/Junction-Ausbruch,
Quelltextauslieferung und Vererbung aller Servervariablen ermöglicht. Der
implementierte Adapter dekodiert URL-Pfade strikt, verwirft kodierte
Trennzeichen, Punkt-/versteckte Segmente und Reparse-Komponenten, erzwingt die
kanonische Dokumentwurzel `www` und sperrt sensible statische Erweiterungen.
PHP wird ohne Shell und ohne offenen CGI-Port über `CreateProcessW` gestartet;
die Kindumgebung besteht nur aus einer Allowlist von CGI-/Systemwerten.
Der Adapter wird nur bei `SOVEREIGN_PHP_ENABLED=1` aktiviert; ein geerbter oder
veralteter CGI-Pfad allein kann ihn nicht implizit einschalten.
Statische Dateien werden ebenfalls nur aus einer positiven Allowlist üblicher
Web-, Schrift- und Medienformate ausgeliefert; Quell-, Template- und
Konfigurationsformate wie `.inc`, `.twig`, `.yaml` oder `.ini` bleiben gesperrt.

### Mittel: HTTP-Request-Smuggling und Body-Ambiguität

Der Rust-Parser akzeptiert höchstens eine kanonische dezimale
`Content-Length` bis 16 MiB und lehnt `Transfer-Encoding`, führende Nullen,
Duplikate und Bodies für Nicht-Body-Methoden ab. C++ trennt Header und Body,
liest exakt diese Bytezahl innerhalb einer absoluten 30-Sekunden-Deadline und
verwirft überzählige Bytes. Die reservierten internen Endpunkte bleiben
bodylos; nur der PHP-Pfad erhält den validierten Body.

### Mittel: unbegrenzte Verbindungs-, Queue- und Prozessressourcen

Admission erfolgt direkt nach `accept`, bevor ein Socket die begrenzte
Threadpool-Queue erreicht. Header-, Body- und Verbindungsdeadlines,
Requestanzahl, Workerzahl, Go-Queues, Rate-Limiter-Identitäten und EventHub sind
begrenzt. PHP besitzt eine atomare Prozesskapazität, 30 Sekunden Laufzeit,
384 MiB Prozessspeicher, genau einen aktiven Prozess je Job und 16 MiB
Request-/Responsegrenzen. Überlast schlägt geschlossen fehl.

### Mittel: manipulierbare Modulpfade und Archive

Die Installation prüft den erwarteten SHA-256 vor dem Entpacken, verhindert
absolute Pfade, `..`, ADS/Drive-Pfade, Zieldubletten, ZIP-Bombs und Ausbruch aus
dem Staging-Verzeichnis. Aktivierte Versionen benötigen einen konsistenten
Installationsbeleg; dessen Pfade müssen im Versionsordner bleiben. x64-PE-Format
und SHA-256 des tatsächlich gestarteten Einstiegspunkts werden erneut geprüft.

### Weitere behobene Befunde

- JWT-Pflichtclaims, Ablauf, kanonische Claim-Struktur und Mindestschlüssellänge
  werden fail-closed validiert; nur positive Verifikation gilt als Erfolg.
- Absolute Fünf-Sekunden-Header- und 60-Sekunden-Verbindungsdeadlines schließen
  den früher möglichen Slowloris-Pfad.
- `SO_EXCLUSIVEADDRUSE` ersetzt die konkurrierende Windows-Portfreigabe.
- Dynamische JSON-Werte werden korrekt maskiert; Headerwerte durchlaufen eine
  zentrale CR/LF- und Syntaxprüfung.
- PHP-CGI-Header dürfen keine Hop-by-hop-, Server-, Längen- oder
  Transfer-Encoding-Werte überschreiben.
- MariaDB deaktiviert `local_infile`, begrenzt `secure_file_priv`,
  Paketgröße/Verbindungen und Namensauflösung. Daten, Temp und Logs liegen auf
  F:; Secrets liegen nicht in `state.json`. Das Control Center erzeugt für das
  CMS eine eigene Datenbank und einen auf diese Datenbank begrenzten Benutzer.
- Der Manager beendet nur Prozesse, deren PID und kanonischer Programmweg noch
  zum gespeicherten Dienst passen.

## Drittanbieter und Provenienz

Verwendet werden die offiziellen Windows-x64-Pakete:

- PHP 8.4.27 NTS, Archiv-SHA-256
  `DBAE154A0A89791F36C3D48E68BAE797878333E7D6CB5721E74617DE59B63AB7`
- MariaDB 11.8.9, Archiv-SHA-256
  `830C46727D9278EAE212AE3ECA44EEB9E71B2A68704E95F344A64FBA7B1963F5`

Beide Archive wurden vor dem Entpacken gegen die Herstellerwerte geprüft. Die
internen Binärimplementierungen dieser Drittprodukte wurden nicht
quelltextbasiert auditiert; Versionspflege bleibt daher Teil des Betriebs.

## Coverage Ledger

| Angriffsfläche | Status | Ergebnis |
|---|---|---|
| Authentication / Session | COMPLETE | Ausgabe, Prüfung, Ablauf, Secretquelle und PHP-Nichtvererbung verfolgt |
| Authorization / reservierte Routen | COMPLETE | API-/WS-Pfade bleiben vom CMS-Router getrennt und geschützt |
| HTTP / Parser / Smuggling | COMPLETE | Request-Line, Header, CL/TE, Body, Keep-Alive und Deadlines geprüft |
| Dateien / Traversal / Upload | COMPLETE | Dokumentwurzel, Encoding, Reparse-Punkte, statische Typen und Front-Controller geprüft |
| PHP-CGI / IPC / Prozesse | COMPLETE | Kommando, Pipes, Umgebung, Jobgrenzen, Timeout und Responseparser geprüft |
| Secrets / Config / Admin | COMPLETE | Env, DPAPI, Logs, Managerstatus und Startbedingungen geprüft |
| Datenbankkonfiguration | COMPLETE | Bindung, Import, Temp/Datenpfade, Limits und Initialisierungspfad geprüft |
| Kryptografie / JWT | COMPLETE | SHA/HMAC, Vergleich, Claims, Grenzen und Schlüsselpfad geprüft |
| Native Memory / FFI | COMPLETE | Erreichbare Pointer-, Puffer-, Längen- und Ownership-Pfade geprüft |
| Concurrency / DoS | COMPLETE | Admission, Queues, Atomics, WebSockets, CGI und Go-Ressourcen geprüft |
| Browser / XSS / CSRF | PARTIAL | Serverheader geprüft; die Sicherheit eines später installierten CMS ist nicht Bestandteil dieses Quellstands |
| Drittanbieter-Binärinternas | NOT COVERED | Nur Herkunft, Hash, Archivstruktur und PE-Architektur geprüft |
| Buildartefakt | COMPLETE | Frischer Windows-x64-Build, 6 Quellen/3 Translation Units, SHA-256 und PE-Härtung statisch geprüft |
| Eingebaute Laufzeittests | COMPLETE | Alle 14 C++/Rust/Go-Tests im finalen Build bestanden |
| Netzwerk-Laufzeit | COMPLETE | Vollständiger TCP-Sicherheitstest am finalen Build bestanden |
| PHP-Laufzeit | COMPLETE | Startseite, Front Controller, POST, Secret-Isolation, Traversal und Konfigurationsschutz bestanden |
| MariaDB-/CMS-Laufzeit | COMPLETE | Loopback, Parameter, Schema-/Kontorechte, DPAPI und geordneter Shutdown bestanden |

## Verbleibende Betriebsgrenzen

- Ein installiertes CMS ist ausführbarer, vertrauensrelevanter PHP-Code. Dessen
  Plugins, Themes, Uploadregeln, Benutzerrechte, Datenbankkonten und Updates
  müssen separat geprüft werden; der Server kann deren Logik nicht absichern.
- PHP läuft unter demselben Windows-Benutzer wie der Server. `open_basedir`,
  deaktivierte Prozessfunktionen und das Jobobjekt reduzieren die Angriffsfläche,
  bilden aber keine vollwertige Betriebssystem-Sandbox.
- `allow_url_fopen` bleibt für CMS-Kompatibilität aktiv; nicht vertrauenswürdiger
  CMS-Code kann dadurch ausgehende Requests auslösen.
- Das offizielle MariaDB-Initialisierungsprogramm erhält das zufällige
  Root-Passwort kurzzeitig als Kommandozeilenargument. Es wird danach nur
  DPAPI-geschützt gespeichert; Prozesse desselben Windows-Benutzers stellen
  ohnehin keine getrennte Sicherheitsgrenze dar.
- Die globale CMS-kompatible CSP erlaubt Inline-Skripte und Inline-Styles. Ein
  konkretes CMS sollte später eine engere, an seine Assets angepasste Policy
  erhalten.
- Control Flow Guard ist im aktuellen Build nicht aktiviert;
  dies ist eine Härtungsoption der externen KR-Toolchain.

## Abschließende Verifikation

Der finale Benutzer-Build vom 7. November 2026 war erfolgreich: sechs
`.kr`-Dateien, drei Translation Units, EXE-Größe 7.999.133 Byte und SHA-256
`1BCADB4183F672443D6DF2312320E1335C9B2BB1D9C0B06519B1241396281A12`.
Die PE ist x64/PE32+, Large-Address-Aware und besitzt High-Entropy-ASLR,
Dynamic-Base-ASLR, DEP/NX sowie einen Stack-Protector-Marker. In den generierten
Rust-/Go-Manifests sind keine externen Bibliotheksabhängigkeiten eingetragen.

Die eingebaute Test-Suite wurde anschließend vom Benutzer ausgeführt. Alle 14
Tests für Header-Injection, Traversal-Sanitizer, SHA-256, WebSocket-Handshake,
JWT, Rate Limiter, Go-Admission/Queues/EventHub/Metriken sowie die negativen
HTTP-, WebSocket- und JWT-Fälle wurden bestanden.

Der rohe TCP-Integrationstest wurde ebenfalls vollständig bestanden. Bestätigt
sind Admission vor der Pending-Queue, geschützte Token-/Task-Routen, gültige und
ungültige JWTs, CL/TE-Abwehr, bodylose interne Endpunkte, Ablehnung überzähliger
Bytes, Host-Pflicht und lokale Host-Allowlist, eindeutige Request-Lines,
JSON-Escaping, authentifizierte WebSocket-Grenzen, Slowloris-Deadline sowie die
Ablehnung fehlender Secrets und nichtlokaler Bindungen.

Der erste PHP-Integrationstest erreichte `php-cgi`, erhielt für `/` jedoch
HTTP 403. PHPs Fehlerlog meldete, dass das Primärskript nicht geöffnet werden
konnte. Ursache war die gleichzeitig gesetzte Kombination aus geprüftem
`SCRIPT_FILENAME=...\www\index.php`, absolutem `doc_root` und dem falschen
`PATH_INFO=/`. PHP 8.4 bildet bei absolutem `doc_root` sein Primärskript aus
`doc_root + PATH_INFO` und versuchte daher, das Verzeichnis statt `index.php`
zu öffnen. Das Gateway übergibt nun kein künstliches `PATH_INFO` mehr:
`SCRIPT_NAME` bezeichnet das bereits kanonisch geprüfte Skript und
`REQUEST_URI` bewahrt die ursprüngliche CMS-Route. Der Test enthält zusätzlich
eine Front-Controller-Route. C++20-Syntaxprüfung und alle PowerShell-Parser
sind nach der Änderung fehlerfrei. Der anschließende PHP-Integrationstest
bestand Startseite, Front-Controller-Route, POST-Body, Ausschluss der
Server-Secrets aus der CGI-Umgebung, Traversal-Abwehr und Schutz nicht
auslieferbarer Konfigurationsdateien vollständig.

Der MariaDB-Test deckte zunächst einen realen Portkonflikt mit einer bereits
installierten MySQL-8.3-Instanz auf. `mariadb-admin ping` kann einen erreichbaren
Server trotz fehlgeschlagener Authentisierung als lebend melden und war deshalb
kein ausreichender Besitznachweis. Der Stack verwendet nun den freien Port
3308, verweigert belegte Ports vor dem Start und akzeptiert Bereitschaft nur
nach authentisierter SQL-Abfrage, Loopback-Prüfung und PID-Zuordnung. Der finale
Test bestand Initialisierung auf F:, authentisierte Bereitschaft,
Loopback-Bindung, `local_infile=0`, begrenztes `secure_file_priv`, dediziertes
CMS-Schema, verweigerten Zugriff des CMS-Kontos auf `mysql.user`,
DPAPI-Speicherung und geordneten Shutdown. Danach blieben weder Dienststatus
noch Listener auf Port 3308 zurück.

Der abschließende Regressionslauf auf dem finalen Build bestand anschließend
alle 14 internen C++/Rust/Go-Tests. Auch der vollständige TCP-Sicherheitstest
bestand Admission, Authentisierung und Autorisierung, HTTP-Framing- und
Host-Abwehr, JSON-Escaping, WebSocket-Negativfälle, Slowloris-Deadline sowie
die Fail-Closed-Startbedingungen erneut vollständig. Damit sind alle für
diesen Quellstand vorgesehenen statischen und dynamischen Prüfungen
abgeschlossen; offen bleiben ausschließlich die oben dokumentierten
Betriebsgrenzen und die separate Prüfung eines künftig installierten CMS.

Nach dem Audit zeigte der Control-Center-Start unter Windows PowerShell 5.1
eine Laufzeitinkompatibilität: Anders als PowerShell 7 lädt diese Umgebung die
Assembly mit `System.Security.Cryptography.ProtectedData` nicht automatisch.
Der Stack lädt DPAPI nun explizit aus der jeweils verfügbaren Assembly
(`System.Security.Cryptography.ProtectedData` oder `System.Security`). Die
Interoperabilität wurde praktisch bestätigt, indem Windows PowerShell 5.1 ein
64 Zeichen langes DPAPI-Secret erzeugte und PowerShell 7 dasselbe Secret
erfolgreich entschlüsselte; der Secretwert wurde dabei nicht ausgegeben. Ein
fehlendes Bootstrap-Token wird vom Anzeigeweg nun ebenfalls sicher erzeugt.
