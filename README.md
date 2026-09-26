[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# stratum

**stratum** ist ein forensisches Kommandozeilen-Werkzeug zur automatisierten Inhaltsanalyse eines entschlüsselten Roh-Images (`.dd`, Windows/NTFS). Der Zugriff erfolgt ausschliesslich lesend, jeder Fund trägt seine Herkunft (Byte-Offset und Quelle), und die Ausgabe ist ein JSON-Report, der sich direkt weiterverarbeiten lässt.

Das Werkzeug schliesst an [ForensiCUnlock](https://github.com/yalmn/ForensiCUnlock) an: dessen `merged.dd` (das entschlüsselte Gesamt-Image) ist die Eingabe für stratum.

## Grundsätze

- **Read-only.** Das Image wird nie schreibbar geöffnet. Es gibt keinen Loop-Mount im Host-Kernel; die Dateisysteme werden per Bibliothek selbst geparst.
- **Integrität zuerst.** Vor der Analyse werden SHA-256 und BLAKE3 über das gesamte Image gebildet und im Report festgehalten.
- **Nachvollziehbarkeit.** Jeder Fund nennt seinen Byte-Offset und seine Quelle. Zeitzonen stammen aus der Registry, nicht aus der Systemzeit des Analyserechners.
- **Defensiv.** Die Parser lesen nicht vertrauenswürdige Eingaben: Längen werden geprüft, es gibt keine Panics auf angreiferkontrollierten Werten, und die Parser sind über `cargo-fuzz` fuzzbar.

## Funktionsumfang

| Bereich | Beschreibung |
|---|---|
| Integrität | SHA-256 und BLAKE3 über das ganze Image, parallel und streamend |
| Partitionen | MBR und GPT (512- und 4096-Byte-Sektoren), Volume ohne Tabelle, Dateisystem-Hinweis (NTFS, FAT, exFAT, ReFS, BitLocker) |
| NTFS | gezielter Zugriff auf einzelne Dateien per Pfad, ohne Einhängen |
| Registry | eigener regf-Parser, Zugriff per Pfad, Zeitzone und Rechnername |
| Konten | lokale Windows-Konten mit Benutzername und NT-Hash aus SAM und SYSTEM |
| Artefakt-Domänen | Autostart, USB, Programmausführung (Amcache, Shimcache, Prefetch, BAM/DAM), Benutzeraktivität (UserAssist, TypedURLs, TypedPaths, RunMRU, WordWheelQuery, RecentDocs), EventLog, Browser-Verlauf und -Passwörter, LSA/DCC2, DPAPI, Tor, Volume Shadow Copies |
| Keyword-Suche | Begriffe aus einer Tabelle, in ASCII und UTF-16LE, Zugangsdaten als Paar (Benutzer- und Passwort-Feld in geringem Abstand), validierte v3-Onion-Adressen |

Die Begriffe für die Suche stehen bewusst nicht im Code, sondern in einer pro Fall gepflegten und versionierten TOML-Tabelle. So bleibt nachvollziehbar, wonach gesucht wurde, und das Rauschen lässt sich pro Fall über die aktiven Kategorien steuern. Eine Beispieltabelle liegt unter `search/examples/begriffe.toml`.

## Aufbau

Cargo-Workspace aus mehreren Crates:

```
mmap/      Read-only Memory-Mapping (einzige unsafe-Grenze, gekapselt)
core/      Image-IO, Hashing, Partitionen, Analyzer-Trait
registry/  Parser für Windows-Registry-Hives (regf)
ntfs/      NTFS-Zugriff, Datei per Pfad lesen
search/    Keyword- und Muster-Suche
creds/     lokale Windows-Konten aus SAM und SYSTEM
cli/       Binary "stratum", JSON-Report
fuzz/      cargo-fuzz-Targets
```

Neue Artefakt-Analysen werden als eigene Implementierung des `Analyzer`-Traits ergänzt, der Kern bleibt unberührt.

## Bauen

Voraussetzung ist eine aktuelle Rust-Toolchain (Edition 2021).

```sh
cargo build --release
```

Das Binary liegt danach unter `target/release/stratum`.

## Verwendung

```sh
stratum <image.dd> [-o report.json] [-k begriffe.toml] [--bdp bdp.info] [--no-hash]
```

| Argument | Bedeutung |
|---|---|
| `<image.dd>` | entschlüsseltes Roh-Image (z. B. `merged.dd`) |
| `-o, --out` | Zieldatei für den JSON-Report (ohne Angabe: Ausgabe auf stdout) |
| `--html` | zusätzlich einen übersichtlichen HTML-Report in diese Datei schreiben |
| `-k, --keywords` | eigene Begriffstabelle (TOML), mehrfach angebbar |
| `--no-default-keywords` | die mitgelieferte Liste nicht verwenden |
| `--raw-sweep` | zusätzlich das ganze Image roh durchsuchen (unallozierte/gelöschte Bereiche) |
| `--check-onion` | gefundene .onion-Adressen online über Tor auf Erreichbarkeit prüfen (opt-in) |
| `--dump <pfad> <ziel>` | eine einzelne Datei aus dem Image extrahieren und beenden (ohne Analyse) |
| `--bdp` | `bdp.info` von ForensiCUnlock, legt die zu analysierende Partition fest |
| `--no-hash` | die Integritäts-Hashes nicht berechnen (spart bei grossen Images Zeit) |
| `--dpapi-password <pw>` | Benutzerpasswort, um gespeicherte Chromium-Passwörter (DPAPI) zu entschlüsseln |
| `--dpapi-sha1 <hex>` | statt des Passworts dessen vorberechneter SHA-1 (UTF-16LE) |
| `--dpapi-masterkey <hex>` | statt des Passworts ein bereits entschlüsselter DPAPI-Masterkey (64 Byte) |
| `--firefox-password <pw>` | Firefox-Hauptpasswort, um gespeicherte Firefox-Passwörter zu entschlüsseln |

Beispiel:

```sh
stratum merged.dd -o report.json --bdp bdp.info
```

Ohne `--bdp` bestimmt stratum die NTFS-Partitionen selbst aus der Partitionstabelle. Mit `--bdp` wird genau die von ForensiCUnlock entschlüsselte Partition ausgewertet.

### Browser-Passwörter (DPAPI)

Die in Chromium-Browsern (Edge, Chrome, Brave, Opera) gespeicherten Passwörter liegen mit AES-GCM verschlüsselt in `Login Data`; der GCM-Schlüssel steckt DPAPI-geschützt in `Local State` und hängt letztlich am Passwort des Benutzers, nicht an dessen NT-Hash. Ohne dieses Passwort weist stratum nur Anzahl und Speicherort aus. Ist das Passwort bekannt (üblicherweise vorher aus dem NT-Hash geknackt), entschlüsselt stratum die komplette Kette selbst:

```sh
stratum merged.dd --bdp bdp.info --dpapi-password 'GefundenesPasswort'
```

Alternativ nimmt das Tool den vorberechneten SHA-1 (`--dpapi-sha1`) oder einen andernorts entschlüsselten Masterkey (`--dpapi-masterkey`) entgegen. Unterstützt ist der heute übliche Pfad (SHA-512 und AES-256, Windows Vista bis 11); ältere Kombinationen werden erkannt und als nicht unterstützt gemeldet.

Die System-Masterkeys unter `Windows\System32\Microsoft\Protect\S-1-5-18` entschlüsselt stratum ohne Benutzerpasswort direkt aus `DPAPI_SYSTEM` (Domäne `dpapi`). Das legt die Grundlage für maschinengebundene DPAPI-Daten und dient zugleich der Qualitätssicherung: es ist derselbe Masterkey-Code wie beim Browser-Pfad. Mit gesetztem `STRATUM_DEBUG` gibt jeder Fund den entschlüsselten Masterkey als Hex aus, sodass er sich gegen ein unabhängiges Werkzeug abgleichen lässt.

Firefox-Passwörter (`logins.json`) sind über `key4.db` verschlüsselt (PBKDF2-HMAC-SHA256 und AES-256 für den Schlüssel, 3DES für die Einträge). stratum entschlüsselt sie ohne Zusatzdaten aus dem Image, solange kein Firefox-Hauptpasswort gesetzt ist. Ist eines gesetzt, wird es mit `--firefox-password` übergeben:

```sh
stratum merged.dd --bdp bdp.info --firefox-password 'Hauptpasswort'
```

### Keyword-Listen

Eine umfangreiche Begriffsliste zu häufigen Deliktsfeldern ist fest eingebaut und läuft bei jeder Analyse mit (Kategorien wie Zugangsdaten, Darknet, Kryptowährung, Finanzbetrug, Dokumente, Cybercrime, Waffen und weitere). Die lesbare Fassung liegt unter `begriffe/strafverfolgung.toml`.

Eigene, fallbezogene Begriffe kommen in eine zweite Tabelle und werden zusätzlich übergeben. Die Vorlage dafür ist `begriffe/eigene.toml`:

```sh
stratum merged.dd -o report.json --bdp bdp.info -k eigene.toml
```

Die eingebaute Liste ist ein neutraler Ausgangspunkt, kein fertiger Fallkatalog. Pro Fall lässt sich abschalten, was nicht passt (`aktiv = false`), und mit `--no-default-keywords` deaktiviert man sie ganz. Sensible oder fallbezogene Wortlisten gehören nicht in dieses Repository, sondern in die eigene Tabelle, die getrennt geführt wird. Name und Version der verwendeten Tabellen stehen im Report, damit nachvollziehbar bleibt, wonach gesucht wurde.

## PowerShell-Verlauf und Ereignisquellen

Der PowerShell-Analyzer liest `ConsoleHost_history.txt` sowie weitere
`*_history.txt` unter PSReadLine-Verzeichnissen über den vorhandenen NTFS-Index.
Er erfasst physische UTF-8-Zeilen, Profilzuordnung aus dem Pfad, Zeilennummer,
Byte-Offset innerhalb der Datei, MFT-Nummer und Volume-Offset. Ein Verlaufseintrag
belegt allein weder die Ausführung noch ihren Zeitpunkt oder Erfolg. Mehrzeilige
Eingaben bleiben als einzelne Quellzeilen mit Fortsetzungsmarkierung erhalten.
Abweichende, frei konfigurierte Dateinamen werden nicht automatisch erkannt.

Grenzen: 16 MiB je Verlaufsdatei, 50.000 physische Zeilen, 64 KiB je Zeile.
Überschreitungen und ungültiges UTF-8 erscheinen als Warnungen. Der Analyzer
arbeitet derzeit auf den indizierten Live-NTFS-Volumes, nicht auf Schattenkopien.
Die Standardpfade beschreibt die [PSReadLine-Dokumentation](https://learn.microsoft.com/en-us/powershell/module/psreadline/set-psreadlineoption).

Die Timeline enthält alle unterstützten Zeitfelder eines Funds. `finding_index`
verweist auf den Index im `findings`-Array desselben Reports; `time_key` benennt
das ursprüngliche Zeitfeld. Diese Referenz gilt innerhalb dieses Reports und ist
keine fallübergreifende Kennung. Papierkorb-, Registry- und LNK-Zeiten bleiben
als unterschiedliche Ereignisarten erhalten. Zeitliche Nähe allein belegt
keinen ursächlichen Zusammenhang.

Dienste mit ImagePath und geplante Aufgaben bleiben auch bei gewöhnlichem
Programmpfad erhalten. `auffaellig` ist eine Pfadheuristik für die Sichtung und
keine Aussage über Schadsoftware. Dadurch kann die Zahl der Persistenzfunde
steigen; eine spätere Oberfläche kann die Bewertung unabhängig filtern.

## Weiterer Ausbau

Geplant, noch nicht implementiert:

- Weitere Windows-Artefakte: USN/MFT, SRUM, ActivitiesCache, WebCache.
- Dateibasierte Analyse von Schattenkopien.
- Linux-Dateisysteme und Serviceanalysen für Web, Datenbanken, Authentifizierung,
  VPN und Gateways.
- Chat-Artefakte, unter anderem WhatsApp, Signal und Threema. Erkennung,
  unterstützte Formate und Verfügbarkeit erforderlicher Schlüssel getrennt berichten.
- Browseroberfläche mit Dateiexplorer und quellenbezogener Fallauswertung.
- Protokollierung von Analystenaktionen mit Fall, Identität, Zeitpunkt, Quelle,
  Aktion und Ergebnis; Untersuchungszeit getrennt von Artefaktzeiten.
- Promptgestützte Abfragen und Korrelationen mit Verweisen auf die zugrunde
  liegenden Funde. Vermutungen getrennt von belegten Beziehungen darstellen.

GUI, Protokollierung und Korrelationsmodell werden vor ihrer Umsetzung gesondert
abgestimmt. Die Analyselogik bleibt unabhängig von der Oberfläche.

## Report-Integrität

Beim Schreiben in eine Datei (`-o`) legt stratum neben dem Report eine
Prüfsummen-Datei `<report>.sha256` mit SHA-256 und BLAKE3 des Reports an und gibt
den SHA-256 auf der Fehlerausgabe aus. So ist für die Beweiskette belegbar, dass
der Report unverändert ist.

Für die Weiterverarbeitung in Cortex XSOAR liegt unter `xsoar/` eine Vorlage
(Automation, Playbook), die den JSON-Report einliest, `.onion`-Adressen als
Indikatoren anlegt und den Incident bei Belegen für einen Hidden Service
hochstuft.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Jeder Parser hat Unit-Tests gegen synthetische Fixtures und mindestens einen Integrationstest. Die Krypto-Bausteine der Konten-Extraktion sind gegen veröffentlichte Testvektoren geprüft. Die abschliessende Bestätigung der Konten gegen echte Hives (Vergleich mit `samdump2` oder `secretsdump.py`) gehört auf die Analyse-Umgebung.

Die Fuzz-Targets liegen unter `fuzz/` und brauchen eine nightly-Toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run hive
```

Der PowerShell-Test gegen ein erzeugtes NTFS-Volume benötigt `mkntfs` und
`ntfscp`. Er ist explizit auszuführen und schlägt bei fehlenden Werkzeugen fehl:

```sh
cargo test -p stratum-analysis --test powershell_ntfs -- --ignored
```

Der zusätzliche Mini-Image-Test prüft read-only Zugriff, Dateipositionen und
Serialisierung ohne externe Werkzeuge. Das Fuzz-Target heißt `powershell`.

## Lizenz

Dieses Projekt steht unter der [MIT License](LICENSE) © 2025 [yalmn](https://github.com/yalmn/).
