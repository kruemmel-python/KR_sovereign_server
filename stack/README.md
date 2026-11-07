# Sovereign Stack Manager

Dieses Verzeichnis verwaltet optionale Windows-x64-Module fuer den KR-Server.
Der Serverkern bleibt ohne Module startfaehig. PHP und MariaDB werden
versioniert nebeneinander installiert; genau eine Version je Modul kann aktiv
sein.

## Sicherheitsmodell

- Installationen akzeptieren nur lokale ZIP-Dateien mit explizit angegebenem
  SHA-256-Wert.
- ZIP-Pfade, ADS/Drive-Pfade, Duplikate, Dateianzahl und entpackte Groesse
  werden vor dem Schreiben geprueft.
- Ausfuehrbare Einstiegspunkte muessen gueltige Windows-x64-PE-Dateien sein.
- Aktivierung erfolgt erst nach vollstaendiger Pruefung und Installationsbeleg.
- PHP wird pro Request als begrenzter CGI-Kindprozess gestartet; es
  gibt keinen offen erreichbaren FastCGI-Port.
- MariaDB bindet nur an `127.0.0.1`; `local_infile` ist deaktiviert und
  `secure_file_priv` wird auf ein eigenes Importverzeichnis begrenzt.
- Passwoerter werden nicht in `state.json` gespeichert, sondern mit Windows
  DPAPI fuer das aktuelle Benutzerkonto geschuetzt.

`catalog.json` dokumentiert die verwendeten offiziellen Herstellerpakete und
deren vor dem Entpacken verifizierte SHA-256-Werte. Die aktiven Versionen stehen
in `state.json`; ein Start prüft Installationsbeleg, x64-PE-Format und den Hash
des tatsächlichen Einstiegspunkts erneut.

## Bedienung

`SovereignStackManager.bat` im Projektwurzelverzeichnis öffnet das lokale
Control Center. Dort lassen sich Server und MariaDB starten/stoppen, die
Datenbank erstmalig initialisieren, eine eigene `sovereign_cms`-Datenbank mit
eingeschränktem Zufallspasswort-Benutzer anlegen und lokale, vorher heruntergeladene
Modul-ZIPs nach Hashprüfung installieren oder aktivieren. TEMP, TMP, Logs,
Sessions, Daten und Paketablage bleiben unter `F:\...\KR_sovereign_server\stack`.
