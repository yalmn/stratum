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
| Image-Formate | Rohimage (dd) und Expert Witness (E01, auch mehrteilig), erkannt an der Signatur |
| Integrität | SHA-256 und BLAKE3 über das ganze Image, parallel und streamend; bei E01 zusätzlich Abgleich mit dem Akquise-MD5/SHA-1 |
| Partitionen | MBR und GPT (512- und 4096-Byte-Sektoren), Volume ohne Tabelle, Dateisystem-Hinweis (NTFS, FAT, exFAT, ReFS, BitLocker) |
| NTFS | gezielter Zugriff auf einzelne Dateien per Pfad, ohne Einhängen |
| Registry | eigener regf-Parser, Zugriff per Pfad, Zeitzone und Rechnername |
| Konten | lokale Windows-Konten mit Benutzername und NT-Hash aus SAM und SYSTEM |
| Artefakt-Domänen | Autostart, USB, Programmausführung (Amcache, Shimcache, Prefetch, BAM/DAM), Benutzeraktivität (UserAssist, ShellBags, ActivitiesCache, TypedURLs, TypedPaths, RunMRU, WordWheelQuery, RecentDocs), Ressourcennutzung (SRUM), EventLog, Browser-Verlauf (auch WebCache) und -Passwörter, LSA/DCC2, DPAPI, Tor, Volume Shadow Copies |
| Keyword-Suche | Begriffe aus einer Tabelle, in ASCII und UTF-16LE, Zugangsdaten als Paar (Benutzer- und Passwort-Feld in geringem Abstand), validierte v3-Onion-Adressen |

Die Begriffe für die Suche stehen bewusst nicht im Code, sondern in einer pro Fall gepflegten und versionierten TOML-Tabelle. So bleibt nachvollziehbar, wonach gesucht wurde, und das Rauschen lässt sich pro Fall über die aktiven Kategorien steuern. Eine Beispieltabelle liegt unter `stratum_backend/search/examples/begriffe.toml`.

## Aufbau

Das Projekt ist in Teile gegliedert: `stratum_backend/` mit Analyse-Engine,
Server und CLI, `stratum_model/` mit dem gemeinsamen Datenmodell und
`stratum_frontend/` mit der Weboberfläche. Das Cargo-Workspace liegt im
Wurzelverzeichnis, Build-Befehle und `target/` bleiben dort.

```
stratum_backend/
  mmap/      Read-only Memory-Mapping (einzige unsafe-Grenze, gekapselt)
  core/      Image-IO, Hashing, Partitionen, Analyzer-Trait
  registry/  Parser für Windows-Registry-Hives (regf) und ihre Transaktionslogs
  ese/       Parser für ESE-Datenbanken (SRUM, WebCache)
  vss/       Parser für Volume Shadow Copies
  ewf/       Leser für Expert-Witness-Images (E01)
  ntfs/      NTFS-Zugriff, Datei per Pfad lesen
  search/    Keyword- und Muster-Suche
  creds/     lokale Windows-Konten aus SAM und SYSTEM
  analysis/  Domänen-Analyzer und gemeinsamer Kontext
  normalize/ Abbildung der Funde auf das Datenmodell
  store/     PostgreSQL: Modell, Fälle, Evidence, Konten, Rollen, Audit
  lauf/      ein Analyselauf als Bibliothek (Image bis Report, Datenbank),
             genutzt von CLI, Worker und Server
  jobs/      Worker: führt Jobs aus der Warteschlange in PostgreSQL aus
  server/    HTTP-API (/api/v1) auf Axum
  cli/       Binary "stratum": Optionen, Anmeldung, Ausgabe
  fuzz/      cargo-fuzz-Targets
  begriffe/  Begriffslisten für die Keyword-Suche
  xsoar/     Vorlage für Cortex XSOAR
stratum_frontend/
  src/       Weboberfläche (React, TypeScript, Vite, TanStack Query)
stratum_model/
  src/       Fall, Evidence, Artefakte, Observationen, Entitäten,
             Ereignisse, Beziehungen, Findings, Herkunft, Zeitangaben, IDs
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
| `--dump-record <volume_offset> <mft> <ziel>` | eine Datei über Volume-Offset und MFT-Nummer extrahieren (Werte aus dem Katalog) |
| `--fund <kennung>` | einen Rohfund aus einem Report ausgeben; der Pfad ist dann der Report. Die Kennung wird aus dem Inhalt nachgerechnet |
| `--masterkey <guid>` | einen DPAPI-System-Masterkey entschlüsseln und mit Fundstelle und verwendetem Schlüssel ausgeben |
| `--catalog <datei>` | Dateikatalog aller Dateien und Verzeichnisse als JSON Lines schreiben |
| `--datei-hashes` | im Katalog zusätzlich SHA-256 und Signaturtyp jeder Datei bestimmen (liest alle Inhalte, dauert lange) |
| `--mft-timeline <datei>` | vollständige SI-/FN-MACB-Zeitachse einschließlich gelöschter MFT-Datensätze schreiben |
| `--usn-journal <datei>` | `$UsnJrnl:$J` aller NTFS-Volumes als JSON Lines schreiben |
| `--bdp` | `bdp.info` von ForensiCUnlock, legt die zu analysierende Partition fest |
| `--no-hash` | die Integritäts-Hashes nicht berechnen (spart bei großen Images Zeit) |
| `--dpapi-password <pw>` | Benutzerpasswort, um gespeicherte Chromium-Passwörter (DPAPI) zu entschlüsseln |
| `--dpapi-sha1 <hex>` | statt des Passworts dessen vorberechneter SHA-1 (UTF-16LE) |
| `--dpapi-masterkey <hex>` | statt des Passworts ein bereits entschlüsselter DPAPI-Masterkey (64 Byte) |
| `--firefox-password <pw>` | Firefox-Hauptpasswort, um gespeicherte Firefox-Passwörter zu entschlüsseln |

Beispiel:

```sh
stratum merged.dd -o report.json --bdp bdp.info
```

Ohne `--bdp` bestimmt stratum die NTFS-Partitionen selbst aus der Partitionstabelle. Mit `--bdp` wird genau die von ForensiCUnlock entschlüsselte Partition ausgewertet.

### Dateikatalog

`--catalog katalog.jsonl` schreibt je Datei und Verzeichnis eine JSON-Zeile:
Volume-Offset, MFT-Nummer und Sequenz, Elternverzeichnis, Pfad, Größe des
unbenannten Datenstroms, Zeiten aus `$STANDARD_INFORMATION` (`si`) und
`$FILE_NAME` (`fn`), Dateiattribute, benannte Datenströme (z. B.
`Zone.Identifier`), Zahl der Hardlinks und den Image-Offset des MFT-Datensatzes.
Zeiten stehen als ISO 8601 in UTC mit 100-ns-Auflösung. Abweichungen zwischen
`si` und `fn` können auf nachträglich veränderte Zeitstempel hinweisen, sind
aber für sich allein kein Beleg.

Der Katalog liest nur MFT-Datensätze, keine Dateiinhalte; die Integrität des
Beweismittels sichert der Hash über das ganze Image. Mit `--datei-hashes`
tragen Dateien zusätzlich den SHA-256 ihres vollständigen logischen Inhalts.
Das liest jede Datei ganz und dauert bei einem Windows-System entsprechend
lange. Einzelne Dateien lassen sich stattdessen gezielt extrahieren und hashen
(siehe unten). `dateityp` wird aus einer festen Signatur im Inhalt bestimmt, nicht aus der
Dateiendung. Bei einem erkannten Typ nennen `signatur.offset` und
`signatur.bytes` die dafür verwendeten Bytes; `mime` wird nur für Formate mit
eindeutiger Zuordnung ausgegeben. Ohne unterstützte Signatur steht
`dateityp` auf `unbekannt`. Kann der Inhalt nicht vollständig gelesen werden,
fehlt der Hash und `hash_fehler` beschreibt die Ursache. Die Signaturprüfung
ist auf die ersten 64 KiB begrenzt; SHA-256 umfasst unabhängig davon die ganze
Datei.

NTFS führt je Datenstrom eine gültige Datenlänge (Valid Data Length). Ist sie
kleiner als die Dateigröße, etwa bei vorab vergrößerten und nur teilweise
beschriebenen Dateien, liefert Windows dahinter Nullen, auch wenn in den
belegten Clustern noch alte Daten stehen. stratum liest genauso, damit Inhalt
und SHA-256 mit dem übereinstimmen, was Windows selbst ausgibt. Der Katalog
nennt dann mit `--datei-hashes` das Feld `gueltige_laenge`. Die Altdaten dahinter gehören zum Slack und
werden hier nicht ausgewertet.

Vom System komprimierte Dateien (WOF, etwa CompactOS) tragen `wof` mit dem
Verfahren und `reparse_tag`. Beim Lesen entpackt stratum sie aus dem Strom
`WofCompressedData` (XPRESS4K, XPRESS8K, XPRESS16K). LZX und WIM-gestützte Dateien
werden nicht entpackt und als Fehler gemeldet, nie als leerer Inhalt.

Der Katalog enthält nur Einträge, die über den Verzeichnisbaum erreichbar sind,
keine gelöschten MFT-Datensätze. Er ist nach Volume und Pfad sortiert, so dass
dasselbe Image immer dieselbe Datei ergibt. Der Report verweist unter `catalog`
mit SHA-256, BLAKE3 und Zählern auf die Datei. Ist ein Datensatz nicht lesbar,
bleibt der Eintrag mit dem Feld `fehler` erhalten. Verzeichnisse, deren
Index nicht lesbar war, tragen `inhalt_fehler`; ihr Inhalt fehlt im Katalog und
im Pfad-Index, der Report nennt sie zusätzlich unter `warnings`.

Einzelne Dateien lassen sich anschließend gezielt extrahieren:

```sh
stratum merged.dd --bdp bdp.info --dump-record 1048576 123456 ausgabe.bin
```

Neben der Zieldatei entsteht `ausgabe.bin.herkunft.json` mit Quelle
(Volume-Offset, MFT-Nummer, Offset des Datensatzes), SHA-256 und BLAKE3 des
Inhalts, den Artefaktzeiten der Datei und getrennt davon dem Zeitpunkt der
Extraktion. Das gilt auch für `--dump`. Vorhandene Dateien werden nicht
überschrieben. Der Inhalt wird blockweise gelesen und dabei gehasht, eine
Größengrenze gibt es nicht. Nur NTFS- und WOF-komprimierte Dateien werden im
Speicher entpackt und sind auf 256 MiB begrenzt; darüber bricht die Extraktion
mit einer Meldung ab, statt eine gekürzte Datei zu liefern. So lässt sich eine
einzelne Datei aus dem Katalog gezielt auswählen und hashen, ohne alle Inhalte
des Images zu lesen.

### MFT-Volltimeline

`--mft-timeline mft-zeitachse.jsonl` liest den logischen Datenstrom der Master
File Table vollständig. Erfasst werden gültige belegte und gelöschte
FILE-Datensätze. Jede JSON-Zeile beschreibt genau ein MACB-Ereignis aus
`$STANDARD_INFORMATION` oder `$FILE_NAME`: Erstellung (`B`), Inhaltsänderung
(`M`), Metadatenänderung (`C`) oder Zugriff (`A`). FILETIME-Rohwert und UTC-Zeit
mit 100-ns-Auflösung bleiben gemeinsam erhalten.

Jedes Ereignis nennt Volume-Offset, MFT-Nummer, Sequenznummer, Belegungsstatus,
Datensatztyp und den Image-Offset des MFT-Datensatzes. FN-Ereignisse tragen
zusätzlich Name, Namensraum und die Elternreferenz mit deren Sequenznummer.
Aktuelle Pfade stammen aus dem Verzeichnisindex. Historische Pfade werden nur
dann als `rekonstruiert` ausgegeben, wenn die vollständige Elternkette samt
Sequenznummern passt. Andernfalls ist `pfad_status` gleich `unbekannt`; stratum
rät keinen Pfad. DOS-Kurznamen erzeugen keine doppelten Zeitereignisse.

Die Datei ist je Volume chronologisch sortiert. Der Hauptreport verweist unter
`mft_timeline` mit SHA-256, BLAKE3 und Zählern auf sie. Die Analyse liest keine
Dateiinhalte und verändert das Image nicht. Gelöscht bedeutet ausschließlich,
dass das `IN_USE`-Flag im MFT-Kopf nicht gesetzt ist. Es sagt nicht aus, ob der
frühere Dateiinhalt noch vollständig wiederherstellbar ist.

### NTFS-Änderungsjournal

`--usn-journal usn.jsonl` liest den benannten Strom `$Extend\$UsnJrnl:$J`
aller NTFS-Volumes. Jede JSON-Zeile entspricht einem USN_RECORD_V2- oder
USN_RECORD_V3-Datensatz. Enthalten sind USN, UTC-Zeit und roher FILETIME-Wert,
Datei- und Elternreferenz, Dateiname, Änderungsgründe, Dateiattribute,
Journaloffset und physischer Image-Offset. Liegt ein Datensatz über der Grenze
zweier Datenläufe, nennt `image_bereiche` alle Teile als Offset und Länge.
V2-Referenzen werden zusätzlich in
MFT-Nummer und Sequenznummer zerlegt. 128-Bit-Referenzen aus V3 bleiben als
vollständiger Hexwert erhalten und werden nicht als MFT-Nummer interpretiert.

Die Datensätze bleiben in ihrer Reihenfolge im Journal. Mehrere Änderungen
können in einem Datensatz als kombinierte Reason-Flags erscheinen. Eine
Umbenennung besteht üblicherweise aus `RENAME_OLD_NAME` und
`RENAME_NEW_NAME`; stratum bewahrt beide Datensätze getrennt. Das Journal
belegt nur Änderungen, nicht deren Erfolg oder den früheren Dateiinhalt.

Der `$J`-Strom kann einen sehr großen spärlichen Bereich besitzen. stratum liest
nur physisch belegte Datenläufe und materialisiert die Nullbereiche nicht. Die
Ausgabe wird nicht überschrieben und erscheint im Hauptreport mit SHA-256,
BLAKE3, Größen- und Ereigniszählern. Unbekannte Hauptversionen und beschädigte
Datensätze werden gezählt, ohne ein Format zu erraten.

### Download-Herkunft aus `Zone.Identifier`

Benannte NTFS-Datenströme mit dem Namen `Zone.Identifier` werden im normalen
Analyselauf gelesen. stratum wertet den Abschnitt `[ZoneTransfer]` aus und
meldet `ZoneId`, die Windows-Sicherheitszone sowie vorhandene Angaben wie
`HostUrl`, `ReferrerUrl`, `LastWriterPackageFamilyName` und
`AppDefinedZoneId`. Unbekannte Zonennummern und weitere Feldnamen bleiben als
Rohangaben erhalten und werden nicht gedeutet.

Jeder Fund enthält Datei- und Strompfad, Volume-Offset, MFT-Nummer,
MFT-Datensatzoffset, Stromgröße sowie SHA-256 und BLAKE3 des Strominhalts. Der
MFT-Datensatzoffset ist ausdrücklich als Quellenanker gekennzeichnet; bei
nicht-residenten Strömen ist er nicht der physische Offset jedes Nutzdatenbytes.
Die Auswertung ist auf 64 KiB je Strom und 100.000 Funde begrenzt. UTF-8 sowie
UTF-16 mit Byte Order Mark werden unterstützt. Eine gespeicherte Herkunftszone
belegt weder einen erfolgreichen Download noch die Ausführung der Datei.

### Ereignisprotokolle

Aus den `.evtx`-Dateien unter `winevt\Logs` meldet stratum ausgewählte
Ereignisse (Anmeldungen, Konten, Dienste, Protokolllöschung, RDP). Gedeutet
wird nach Anbieter und Ereignisnummer, denn Nummern sind nur innerhalb eines
Anbieters eindeutig: 4625 von `Microsoft-Windows-Security-Auditing` ist eine
fehlgeschlagene Anmeldung, 4625 von `Microsoft-Windows-EventSystem` im
Application-Log nicht. Der Anbieter steht als `anbieter` im Fund. Beteiligte
Personen stehen mit Name, SID und Domäne aus demselben Feldsatz im Fund:
`benutzer` ist der Zielbenutzer, sonst der Ausführende; `ausfuehrender`
zusätzlich, wenn es einen Zielbenutzer gibt; bei Gruppenereignissen
(4728, 4732, 4756) `gruppe` und als `benutzer` das hinzugefügte Mitglied.
Platzhalter wie „-“ und die Null-SID werden nicht übernommen. Jeder Fund
trägt `event_record_id`, die Zeit als `zeit_utc` mit 100-ns-Auflösung und als
FILETIME sowie den Anker der Protokolldatei (Volume-Offset, MFT-Nummer, Offset
des MFT-Datensatzes). `datei_offset` nennt den Beginn des Datensatzes in der
Datei und wird nur gesetzt, wenn EventRecordID und Zeitstempel im Datensatzkopf
genau zu dem passen, was der Parser gelesen hat; der Offset des Fundes ist dann
die zugehörige Stelle im Image. Windows legt die Protokolle häufig
NTFS-komprimiert ab. Dort stehen im Image nur gepackte Bytes, ein Datensatz hat
keine einzelne Image-Stelle; der Fund nennt dann `image_offset_fehlt =
datei_ntfs_komprimiert` und bleibt über Datei-Offset und MFT-Datensatz
nachvollziehbar. Ereignisse ohne bestätigten Offset und nicht lesbare
Protokolle erscheinen als Warnung.

### Browser-Passwörter (DPAPI)

Die in Chromium-Browsern (Edge, Chrome, Brave, Opera) gespeicherten Passwörter liegen mit AES-GCM verschlüsselt in `Login Data`; der GCM-Schlüssel steckt DPAPI-geschützt in `Local State` und hängt letztlich am Passwort des Benutzers, nicht an dessen NT-Hash. Ohne dieses Passwort weist stratum nur Anzahl und Speicherort aus. Ist das Passwort bekannt (üblicherweise vorher aus dem NT-Hash geknackt), entschlüsselt stratum die komplette Kette selbst:

```sh
stratum merged.dd --bdp bdp.info --dpapi-password 'GefundenesPasswort'
```

Alternativ nimmt das Tool den vorberechneten SHA-1 (`--dpapi-sha1`) oder einen andernorts entschlüsselten Masterkey (`--dpapi-masterkey`) entgegen. Unterstützt ist der heute übliche Pfad (SHA-512 und AES-256, Windows Vista bis 11); ältere Kombinationen werden erkannt und als nicht unterstützt gemeldet.

Die System-Masterkeys unter `Windows\System32\Microsoft\Protect\S-1-5-18` entschlüsselt stratum ohne Benutzerpasswort direkt aus `DPAPI_SYSTEM` (Domäne `dpapi`). Das legt die Grundlage für maschinengebundene DPAPI-Daten und dient zugleich der Qualitätssicherung: es ist derselbe Masterkey-Code wie beim Browser-Pfad. Jeder Fund nennt, womit entschlüsselt wurde (Benutzer- oder Maschinenschlüssel aus `DPAPI_SYSTEM`). Den Masterkey selbst gibt der Lauf über das ganze Image nur mit gesetztem `STRATUM_DEBUG` als Hex aus. Einen einzelnen Masterkey ruft `--masterkey <GUID>` jederzeit gezielt ab, etwa zum Abgleich mit einem unabhängigen Werkzeug.

Firefox-Passwörter (`logins.json`) sind über `key4.db` verschlüsselt (PBKDF2-HMAC-SHA256 und AES-256 für den Schlüssel, 3DES für die Einträge). stratum entschlüsselt sie ohne Zusatzdaten aus dem Image, solange kein Firefox-Hauptpasswort gesetzt ist. Ist eines gesetzt, wird es mit `--firefox-password` übergeben:

```sh
stratum merged.dd --bdp bdp.info --firefox-password 'Hauptpasswort'
```

### Keyword-Listen

Eine umfangreiche Begriffsliste zu häufigen Deliktsfeldern ist fest eingebaut und läuft bei jeder Analyse mit (Kategorien wie Zugangsdaten, Darknet, Kryptowährung, Finanzbetrug, Dokumente, Cybercrime, Waffen und weitere). Die lesbare Fassung liegt unter `stratum_backend/begriffe/strafverfolgung.toml`.

Eigene, fallbezogene Begriffe kommen in eine zweite Tabelle und werden zusätzlich übergeben. Die Vorlage dafür ist `stratum_backend/begriffe/eigene.toml`:

```sh
stratum merged.dd -o report.json --bdp bdp.info -k eigene.toml
```

Die eingebaute Liste ist ein neutraler Ausgangspunkt, kein fertiger Fallkatalog. Pro Fall lässt sich abschalten, was nicht passt (`aktiv = false`), und mit `--no-default-keywords` deaktiviert man sie ganz. Sensible oder fallbezogene Wortlisten gehören nicht in dieses Repository, sondern in die eigene Tabelle, die getrennt geführt wird. Name und Version der verwendeten Tabellen stehen im Report, damit nachvollziehbar bleibt, wonach gesucht wurde.

## Registry-Transaktionslogs

Seit Windows 8.1 schreibt Windows Registry-Änderungen zuerst in die
Transaktionslogs (`.LOG1`, `.LOG2`) und erst später, bis zu einer Stunde danach,
in den Hive. Wird ein laufendes oder abgestürztes System gesichert, stehen die
jüngsten Änderungen deshalb nur in den Logs. stratum prüft jeden geladenen Hive
(SYSTEM, SAM, SOFTWARE, SECURITY, Amcache, NTUSER.DAT) wie der Windows-Kern:
Nur wenn der Kopf eine falsche Prüfsumme hat oder die Sequenznummern abweichen,
werden die Logeinträge im Speicher eingespielt. Das Image bleibt unverändert.

Eingespielt werden fortlaufende Einträge ab der Sequenznummer im Kopf der
Logdatei, beide Logs in Sequenzreihenfolge; eine Lücke, eine falsche
Marvin32-Prüfsumme oder eine unplausible Größe beendet das Einspielen. Grundlage
ist die Spezifikation von Maxim Suhanov und für Marvin32 der Referenzcode von
Microsoft. Gegen echte Windows-11-Logs geprüft: alle Prüfsummen stimmen, und
das Einspielen des jüngsten, bereits übernommenen Eintrags ergibt exakt den
Hive im Image.

Unter `windows[].hives` steht je Hive der Zustand (`sauber`, `wiederhergestellt`,
`unsauber_nicht_wiederhergestellt` mit Grund), die eingespielten Sequenzbereiche
und je Logdatei Format, Zahl der Einträge, Prüfsummenfehler und
Sequenzbereich. `neuere_eintraege_ignoriert` zählt Einträge, die neuer als ein
sauberer Hive sind; Windows spielt sie ebenfalls nicht ein. Nach einer
Wiederherstellung beziehen sich Hive-Offsets in Funden auf den
wiederhergestellten Stand, der Report weist darauf hin. Das alte Logformat
(bis Windows 8) wird erkannt, aber nicht eingespielt.

## ShellBags

ShellBags zeigen, welche Ordner ein Benutzer im Explorer geöffnet hat, auch auf
Wechseldatenträgern und im Netz, und bleiben erhalten, wenn der Ordner längst
gelöscht ist. stratum liest den Baum `BagMRU` aus der UsrClass.dat und der
NTUSER.DAT jedes Benutzers (auch aus Schattenkopien) und setzt den Pfad aus der
Folge der Shell Items zusammen. Jeder Eintrag ist ein Fund mit Pfad, Art des
Elements, `bagmru`-Position, Hive-Offset des Werts und des Schlüssels, bei
Ordnern Kurzname, MFT-Datensatz und Sequenz sowie Erstell-, Änderungs- und
Zugriffszeit (`element_*`, FAT-Zeiten in UTC).

`zuletzt_verwendet` ist abgeleitet: die Änderungszeit des Elternschlüssels, die
nur für dessen zuletzt verwendeten Eintrag gilt (erste Stelle in `MRUListEx`);
der Fund sagt das in `zeit_herkunft`. Namen zu Ordner-GUIDs stammen aus
`SOFTWARE\Classes\CLSID` des untersuchten Systems, sonst bleibt die GUID stehen.
Nicht beschriebene Shell Items erscheinen als `unbekannt` mit Rohbytes.

Grundlage ist die Beschreibung des Shell-Item-Formats von libyal (libfwsi).
Gegen echte Windows-11-Daten geprüft: gleiche Einträge und MRU-Zeitpunkte wie
RegRipper `shellbags`; Namen und MFT-Referenzen aus Ordner-Einträgen stimmen
mit dem Dateisystem überein, die FAT-Zeiten mit den NTFS-Zeiten. Netzwerkorte
sind nur nach der Beschreibung umgesetzt.

Derselbe Parser liest die LinkTargetIDList von LNK-Dateien und Jump Lists. Die
Funde tragen `idlist_pfad` und die MFT-Referenz des Ziels als Gegenprobe zum
LinkInfo-Pfad. ANSI-Pfade in LNK-Dateien werden mit der Codepage des
untersuchten Systems gelesen (`Control\Nls\CodePage\ACP`); unterstützt ist
Windows-1252, andere Codepages nennt `zielpfad_kodierung`.

## UserAssist

UserAssist-Einträge der NTUSER.DAT nennen Programme und Verknüpfungen, die ein
Benutzer über die Oberfläche gestartet hat. Die Namen sind ROT13-verschleiert,
stratum gibt Klartext und Rohnamen aus, dazu Quelle mit GUID und Hive-Offset.
Im Format ab Windows 7 (Version 5, 72 Byte) stehen `ausfuehrungen`,
`fokus_anzahl`, `fokus_zeit_ms` und die letzte Ausführung als FILETIME; sie
erscheint als Ereignis `ausgefuehrt` in der Timeline. Microsoft dokumentiert das
Format nicht; die Felder sind gegen RegRipper `userassist` auf echten
Windows-11-Daten geprüft. Andere Versionen und Längen, etwa die
Sitzungsdaten `UEME_CTLSESSION`, bleiben unausgewertet und tragen
`daten_status`.

Viele Namen beginnen mit der GUID eines bekannten Ordners, etwa
`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`. stratum nennt dazu
`knownfolder` (hier `FOLDERID_System`) und `pfad_aufgeloest`
(`C:\WINDOWS\system32\cmd.exe`). Die Standardpfade stammen aus Microsofts
KNOWNFOLDERID-Tabelle, die Variablen darin (`windir`, `ProgramFiles`,
`ALLUSERSPROFILE`, `USERPROFILE`, `APPDATA` und weitere) aus der Registry des
untersuchten Systems. Ordner, deren Standardpfad laut Tabelle nur für 32-Bit-
Systeme gilt oder von der Sprache abhängt, erhalten nur den Namen.

## Windows-Zeitachse (ActivitiesCache)

Je Benutzer liest stratum `ActivitiesCache.db` unter
`AppData\Local\ConnectedDevicesPlatform\<Konto>\`, samt WAL-Datei, in einer
temporären Kopie. Jede Zeile der Tabellen `Activity` und `ActivityOperation`
wird ein Fund mit Tabelle, Zeilennummer (`rowid`), Aktivitäts-ID, Anwendung
aus `AppId`, Typnummer sowie Start, Ende und letzter Änderung als Unix-Zeit in
UTC; diese erscheinen in der Timeline. Der Ablaufzeitpunkt ist ein geplanter
Wert und kein Ereignis. Die Bedeutung der Typnummern ist nicht von Microsoft
dokumentiert und wird nicht gedeutet. Aus JSON-Inhalten werden nur benannte
Felder übernommen (`displayText`, `appDisplayName`, `activeDurationSeconds`
und weitere), binäre Inhalte bleiben als Länge und Anfangsbytes erhalten. Ab
Windows 11 schreibt Windows hier nur noch wenige Aktivitäten.

## SRUM (Ressourcennutzung)

stratum liest jede `SRUDB.dat` auf den NTFS-Volumes, üblicherweise
`Windows\System32\sru\SRUDB.dat`, mit dem eigenen ESE-Parser. Jeder
Datensatz der Anbietertabellen (Tabellennamen als GUID) wird ein Fund mit
allen belegten Spalten, etwa gesendete und empfangene Bytes je Programm oder
CPU-Zeiten und Datenträgerzugriffe. Die Anbieternamen stammen aus
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions` des
untersuchten Systems. `AppId` und `UserId` werden über `SruDbIdMapTable`
aufgelöst: eine gültige SID als SID, sonst UTF-16-Text (Pfad, Dienst- oder
Paketname). Die Typnummer des Eintrags bleibt als Zahl erhalten, Einträge ohne
Inhalt werden als `IdBlob leer` gekennzeichnet.

`TimeStamp` ist ein OLE-Datum und erscheint als `zeitpunkt_utc`. FILETIME-
Spalten (`EndTime`, `StartTime`, `ConnectStartTime`, `EventTimestamp`) stehen
zusätzlich als `<Spalte>_utc`. An echten Daten liegen sie höchstens zehn
Minuten vor diesem Zeitpunkt. SRUM fasst Messwerte zusammen; die Funde
erscheinen deshalb nicht in der Timeline. Jeder Fund trägt Tabelle, Seite,
Datei-Offset und, soweit die Datenläufe bekannt sind, den Image-Offset des
Datensatzes. Textspalten, die laut Katalog nicht UTF-16 sind, aber Nullbytes
enthalten, bleiben als Hex erhalten, die UTF-16-Lesart steht getrennt
daneben. Eine unsauber geschlossene Datenbank wird gemeldet; die SRU-Logdateien
werden nicht eingespielt. Long Values, komprimierte und mehrwertige Spalten
werden als `nicht_ausgewertet` mit ihren Flags ausgegeben.

Geprüft gegen dissect.esedb an einer Windows-11-SRUDB.dat: 5.064 Datensätze
in acht Anbietertabellen, alle Ganzzahlwerte identisch.

## WebCache (WinINet)

Je Benutzer liest stratum `WebCacheV01.dat` unter
`AppData\Local\Microsoft\Windows\WebCache\` mit dem eigenen ESE-Parser. Die
Datenbank sammelt Verlauf, Cache, Cookies und weitere Einträge der
WinINet-Komponente, die Internet Explorer, Edge Legacy, der Explorer und
manche Apps nutzen. Jeder Datensatz jeder Tabelle außer dem Systemkatalog
wird ein Fund mit allen belegten Spalten. Einträge der Container
(`Container_<Id>`) erhalten Name, Verzeichnis und Partition ihres Containers
aus der Tabelle `Containers`.

Verlaufs-URLs der Formen `Visited: <Konto>@<URL>` und
`:<Zeitraum>: <Konto>@<URL>` (Tagesverlauf `MSHist...`) werden in Konto, URL
und Zeitraum zerlegt. Für Cache-Einträge setzt stratum den Pfad der
Cache-Datei aus Containerverzeichnis, Unterordner und `Filename` zusammen
und sucht ihn im Volume (`cache_datei_im_volume`, MFT-Nummer). Der
Unterordner ergibt sich aus `SecureDirectory`, einem bei 1 beginnenden Index
in `SecureDirectories` (Namen zu je 8 Zeichen); an echten Daten geprüft, alle
fünf Dateien lagen dort. Im Container `Content` stimmte die Größe mit
`FileSize` überein, im Container `DOMStore` nicht (13 statt 2.013 Byte).
`FileSize` wird deshalb nur ausgegeben, nicht als Dateigröße gedeutet.

Zeitspalten sind FILETIME in UTC und stehen zusätzlich als `<Spalte>_utc`.
Ausnahme: `ModifiedTime` in `MSHist`-Containern lag in den Testdaten genau
um den UTC-Abstand der Systemzeitzone nach dem Besuch. Sie wird deshalb als
`ModifiedTime_ortszeit` ohne Umrechnung und mit Hinweis ausgegeben. Der
Höchstwert (kein Ablauf) wird nicht als Datum dargestellt. In die Timeline
gehen `AccessedTime` und `CreationTime` der Containereinträge. Herkunft,
Umgang mit unsauber geschlossenen Datenbanken und nicht ausgewerteten Werten
wie bei SRUM; die Übersicht zählt nicht ausgewertete Werte
(`nicht_ausgewertete_werte`).

Geprüft gegen dissect.esedb an einer Windows-11-WebCacheV01.dat: 35
Datensätze, alle Ganzzahlwerte identisch.

## Datenmodell

`stratum_model` beschreibt den Weg von der Evidence zur Bewertung: Evidence,
Artefakt, Observation, Entität und Ereignis, Beziehung, Finding. Jedes
Objekt über der rohen Evidence trägt einen Ableitungsstatus (beobachtet,
geparst, abgeleitet, korreliert, rekonstruiert, vom Analysten gesetzt,
externe Threat Intelligence, Vorschlag eines Sprachmodells) und eine
Herkunft bis zur Fundstelle, bei NTFS mit MFT-Nummer, Datei- und
Image-Offset und gegebenenfalls Schattenkopie. Beobachtetes und
Gefolgertes werden nie gleich behandelt.

IDs: Verwaltungsobjekte (Fall, Evidence-Import, Analyselauf, Finding)
erhalten eine zeitlich sortierbare UUIDv7. Was aus Evidence abgeleitet wird
(Artefakt, Observation, Entität, Ereignis, Beziehung), erhält eine
deterministische UUIDv5 aus Fall, SHA-256 der Evidence und einem
kanonischen Schlüssel. Ein erneuter Lauf über dieselbe Evidence im selben
Fall ergibt dieselben IDs. Entitäten werden über kanonische Schlüssel
identifiziert (Windows-Benutzer: SID vor Domäne und Name vor Name; IP- und
Domänennamen normalisiert; Hashes mit Algorithmus), nie über Anzeigenamen.
Zeitangaben tragen UTC-Zeitpunkt, Originalwert, Genauigkeit und Bedeutung
(Artefaktzeit, Ereigniszeit, Akquisezeit, Analysezeit, Analystenaktion);
Ortszeiten ohne bekannte Zone werden nicht umgerechnet.

Das Modell hängt von keinem Backend-Crate ab; ein Test prüft das.

Artefakte enthalten den Rohfund nicht als Kopie, sondern verweisen mit
`rohfund_id` auf ihn. Die Kennung ist ein Inhaltshash über den Fund; mit
`stratum <REPORT> --fund <KENNUNG>` wird er aus dem Report geholt und die
Kennung nachgerechnet, sodass eine nachträgliche Änderung auffällt. Die
gelesenen Felder stehen zusätzlich in der Observation.

**Normalizer.** Mit `--modell <DATEI>` bildet stratum die Funde (Rohfunde)
auf das Modell ab und schreibt es als JSON; der Report verweist mit Hashes
und Zählern darauf. Abgebildet werden bisher Ereignisprotokolle, Prefetch,
USB, Programmausführung, Benutzeraktivität, Persistenz, Browser, SRUM und
Zugangsdaten:

- Ereignisprotokolle: je Datensatz ein Artefakt und ein Ereignis
  (Anmeldung, Abmeldung, Anmeldeversuch, Prozessstart, Dienst installiert,
  Kontoänderungen, Gruppenmitgliedschaft, Protokolllöschung, RDP) mit
  Benutzer, ausführendem Konto, Rechner, Quell-IP, Programm oder Dienst.
  Systemstart und Herunterfahren sind aus dem Start und Stopp des
  Ereignisprotokolldienstes geschlossen und als abgeleitet markiert.
- Prefetch: letzte Ausführung als Prozessstart des Programms.
- USB: Gerät mit seinen Zeitpunkten, Volume und Laufwerksbuchstabe liegen
  auf dem Gerät (`MountedDevices`), Benutzer nutzt Volume oder Freigabe
  (`MountPoints2`).
- Programmausführung: Amcache als Datei mit SHA-1 und dem Zeitpunkt der
  letzten Änderung des Eintrags, Shimcache als Änderungszeit der Datei
  (beides belegt keine Ausführung), BAM/DAM als letzte Ausführung durch
  den Benutzer mit der SID des Schlüssels.
- Benutzeraktivität: UserAssist als Prozessstart, MRU-Listen der
  NTUSER.DAT (TypedURLs, TypedPaths, RunMRU, WordWheelQuery, RecentDocs,
  ComDlg32), LNK-Dateien, Sprunglisten, ShellBags und ActivitiesCache als
  Nutzung durch den Benutzer. Ein Ereignis gibt es nur, wenn die Zeit
  sicher zum Eintrag gehört: bei MRU-Listen und ShellBags nur für den
  zuletzt verwendeten Eintrag (Änderungszeit des Schlüssels, als abgeleitet
  markiert), bei LNK-Dateien die eigenen Zeiten der Verknüpfung (erstes und
  letztes Öffnen), sonst die Zeiten, die die Quelle selbst nennt. Ziele von
  Verknüpfungen werden mit der Seriennummer ihres Volumes verbunden.
- Persistenz: Dienste, geplante Aufgaben, Run-Schlüssel, Winlogon,
  AppInit_DLLs, IFEO-Debugger und Autostart-Ordner als Entitäten mit Befehl
  und Bewertung. Nennt der Befehl einen absoluten Pfad, führt der Eintrag
  die Datei aus; Pfade mit Umgebungsvariablen werden nicht aufgelöst. Die
  Erstellzeit der Aufgabendatei gilt als Zeitpunkt, zu dem die Aufgabe
  angelegt wurde (abgeleitet). Dienste aus Ereignis 7045 werden über
  Anzeigenamen oder ImagePath dem Registry-Schlüssel zugeordnet, nur wenn
  genau ein Dienst passt.
- Browser: Verlauf aus Chromium, Firefox und den Verlaufscontainern des
  WebCache als Besuch, Cache-, DOMStore- und Cookie-Einträge nur als
  Nutzung der URL. `file:///`-URLs verweisen auf die Datei mit demselben
  Pfad.
- SRUM: jede Zeile als Nutzung mit Programm, Konto und Rechner. Das
  Programm richtet sich nach dem Kennungstyp: Dienst (dieselbe Entität wie
  aus der Registry), App-Paket, Datei oder Programmname; Kennungen der
  App-Timeline (`!!svchost.exe!…`) werden auf den Programmnamen
  zurückgeführt. `TimeStamp` ist als Artefaktzeit gekennzeichnet, weil
  nicht belegt ist, welchen Zeitpunkt er genau festhält.
- Zugangsdaten: LSA-Secrets, gecachte Domänenanmeldungen (DCC2),
  DPAPI-System-Masterkeys und entschlüsselte Browser-Logins als
  Credential-Entitäten mit Status, Länge und den Werten wie im Report
  (Passwort, Hash, Secret, Schlüssel). Sie tragen `sensibel: true`, damit
  der spätere Zugriff gesondert geprüft und protokolliert werden kann.
  Dienstkennwörter (`_SC_<Dienst>`) gehören zum Dienst, Masterkeys zum
  Konto aus dem Pfad, Logins zum Profil und zur URL.

Dateien ohne MFT-Nummer werden über den Pfad zusammengeführt, getrennt nach
Laufwerksbuchstabe (`c:`) und Gerätepfad (`\Device\HarddiskVolume3`). Steht
derselbe Pfad unter beiden, verbindet stratum die Dateien als „möglicherweise
dieselbe“ und kennzeichnet das als Korrelation, weil die Zuordnung von
Buchstabe zu Gerät nicht geprüft ist.

Benutzer werden über die SID zusammengeführt. Nennt eine Quelle nur den
Namen, wird die SID ergänzt, wenn der Name in den Ereignisprotokollen
eindeutig einer SID zugeordnet ist; das steht dann an der Entität. Ohne
`--fall-id` wird die Fall-ID aus dem Image-Hash abgeleitet, sodass Läufe
über dasselbe Image dieselben IDs ergeben. Die Statistik nennt je Domäne,
was abgebildet wurde, was noch keinen Mapper hat und wo die Fundstelle
unvollständig ist.

## Datenbank (PostgreSQL)

Mit `--modell <DATEI> --db` schreibt stratum das Datenmodell zusätzlich in
eine lokale PostgreSQL. Die Analyse selbst braucht keine Datenbank; ohne
`--db` bleibt alles wie bisher.

Die Datenbank läuft per Docker nur auf 127.0.0.1 (`compose.yaml`). Das
Passwort liegt in `.stratum_db_passwort` im Projektverzeichnis (nicht im
Repository); dieselbe Datei nutzt Docker als Secret und stratum über
`STRATUM_DB_PASSWORT_DATEI`. Die Verbindung steht ohne Passwort in
`STRATUM_DB_URL`. Die Datei muss vor `docker compose up` existieren; fehlt
sie, legt Docker an ihrer Stelle einen leeren Ordner an, das Passwort
bleibt leer und der Container startet immer wieder neu. `chmod 644` ist
vorsorglich, damit der Container sie als Benutzer `postgres` lesen kann;
die Datenbank selbst ist nur auf 127.0.0.1 erreichbar:

```sh
openssl rand -hex -out .stratum_db_passwort 24
chmod 644 .stratum_db_passwort
docker compose up -d
export STRATUM_DB_URL=postgres://stratum@127.0.0.1:5432/stratum
export STRATUM_DB_PASSWORT_DATEI=.stratum_db_passwort
stratum merged.dd --modell modell.json --db -o report.json
```

Das Schema legt stratum beim ersten Verbinden über versionierte
Migrationen an. Ein Modell wird in einer Transaktion geschrieben; dank der
abgeleiteten IDs legt ein zweiter Lauf über dieselbe Evidence im selben
Fall nichts doppelt an. Herkunftsangaben speichern Fundstelle und Parser
nur, wenn sie vom Artefakt abweichen; die View `provenance_full` setzt sie
wieder zusammen. `occurred_utc` dient dem Sortieren und ist auf die
Mikrosekunde gerundet; die verlustfreie Zeit mit Originalwert steht in
`occurred_at`. Am Testimage (rund 8.400 Artefakte, 7.600 Ereignisse) dauert
das Schreiben etwa 4 Sekunden und belegt 33 MB.

Zu jedem Lauf legt stratum den Fall (`case_file`) und die Evidence an,
falls es sie noch nicht gibt. Ein Fall hat beliebig viele Evidence-Objekte
verschiedener Art (Images, später Speicherabbilder, Mitschnitte, Logs) mit
Größe, SHA-256, BLAKE3, Akquiseangaben und dem Stand der Auswertbarkeit
(`recognized`, `analyzed`, `unsupported_format`, `key_missing`). Ohne
eigene Angaben heißt der Fall `CLI-<Fall-ID>`, der Ordner des Images gilt
als Fallordner; Titel und Stand eines vorhandenen Falls ändert stratum
nicht. Eine Evidence wird nie verändert: kommt unter derselben ID ein
anderer SHA-256, bricht der Lauf ab. E01 und Rohimage derselben
Mediendaten sind zwei Evidence im selben Fall und werden von selbst als
`SAME_SOURCE` verknüpft; weitere Beziehungen (`DERIVED_FROM`,
`BELONGS_TO`, `PART_OF`) stehen in `evidence_relation`.

Der Analyselauf (`analysis_run`) trägt Beginn, Ende, Stand, die
Konfiguration des Laufs samt SHA-256 (Analyzer, Begriffslisten, Optionen;
Passwörter und Schlüssel nur als Art, nie mit Wert) und den SHA-256 des
Reports. Er beginnt als `running` und wird erst nach dem Schreiben des
Reports `completed`; scheitert der Report, endet er als `failed`. `--db`
geht nur mit Image-Hash, also nicht zusammen mit `--no-hash`.

Findings (`finding`, `finding_ref`) sind fachliche Bewertungen mit Belegen
aus Entitäten, Ereignissen und Artefakten desselben Falls. Ein Vorschlag
eines Sprachmodells (`ai_suggested`) kann kein Finding sein; das prüft die
Datenbank selbst. Ergebnisse späterer Korrelationsregeln landen als
Beziehung oder Ereignis mit `derivation = 'correlated'`, die Regel steht in
der Herkunft.

Mit `--db` steht außerdem der Dateikatalog in der Tabelle `file`, auch
ohne `--catalog` (mit `--catalog` zusätzlich als Datei, beide aus
demselben Durchlauf). Er wird in Blöcken geschrieben, nie als Ganzes im
Speicher gehalten. Zeiten stehen verlustfrei als FILETIME in `bigint`
(100 ns); `filetime_iso(si_modified)` liefert wieder den Text des Katalogs.
Werte mit gesetztem obersten Bit (in Windows ungültig) bleiben bitgleich
erhalten und erscheinen als negative Zahl. Ein späterer Lauf mit
`--datei-hashes` ergänzt fehlende SHA-256-Werte und Dateitypen. Am
Testimage: rund 149.000 Einträge in etwa 13 Sekunden, 92 MB.

### Benutzer, Rollen und Audit

Berechtigungen sind ein fester Katalog, den stratum prüft (`case.create`,
`case.view`, `evidence.import`, `analysis.start`, `file.view`,
`file.extract`, `credential.view_sensitive`, `audit.view`, `audit.verify`
und weitere, siehe `stratum_model::Permission`). Rollen sind frei benannte
Bündel davon: Superadmins legen sie an, ändern und löschen sie und vergeben
sie an Konten. Mitgeliefert werden die Rollen der Zielarchitektur als
änderbare Vorlagen (Administrator, Case Manager, Forensic Examiner,
Analyst, Threat Intel Analyst, Reviewer, Read Only, Automation Service);
sensible Zugangsdaten sind darin nur Administrator und Forensic Examiner
erlaubt.

Menschen registrieren sich selbst (Passwort mindestens 12 Zeichen,
gespeichert als Argon2id). Das Konto bleibt gesperrt (`pending`), bis ein
Superadmin es freigibt und Rollen vergibt; er kann Registrierungen auch
ablehnen und Konten sperren. Superadmins dürfen alles und verwalten Konten
und Rollen; das hängt an keiner Rolle, und der letzte aktive Superadmin
lässt sich weder sperren noch herabstufen. Den ersten Superadmin richtet
das Systemkonto `stratum-cli` ein. Dienstkonten haben kein Passwort.

Die Kommandozeile arbeitet bis auf Weiteres ohne Anmeldung als
`stratum-cli` mit der Rolle Automation Service; wer sie aufgerufen hat,
steht als Benutzer des Betriebssystems im Audit. Fehlt einem Konto eine
Berechtigung, wird die Aktion abgelehnt und als `denied` protokolliert.

Bedienung über Unterbefehle (die bisherige Form `stratum IMAGE …` bleibt
unverändert). Verwaltende Befehle laufen als angemeldetes Konto (`--als
NAME`); Passwörter werden verdeckt abgefragt oder mit `--passwort-datei`
bzw. `--als-passwort-datei` aus einer Datei gelesen, nie als Argument:

```sh
stratum superadmin einrichten chef --anzeigename "Vorname Name"
stratum konto registrieren mia --anzeigename "Mia M."
stratum konto liste --als chef
stratum konto freigeben mia --rolle Analyst --als chef
stratum rolle anlegen Fallführung --recht case.create --recht case.view --als chef
stratum konto rollen mia --rolle Analyst --rolle Fallführung --als chef
stratum superadmin uebertragen mia --als chef
stratum rolle liste
stratum rechte
stratum audit liste --anzahl 50 --als mia
stratum audit pruefen
```

Fälle und Evidence:

```sh
stratum fall neu DFIR-2026-0017 --titel "Webserver-Einbruch" --ordner /faelle/0017 --als chef
stratum evidence hinzu DFIR-2026-0017 /faelle/0017/merged.dd --rolle Webserver --als mia
stratum evidence hinzu DFIR-2026-0017 /faelle/0017/mitschnitt.pcapng --rolle Gateway --als mia
stratum fall zeigen DFIR-2026-0017 --als mia
stratum fall liste --als mia
stratum /faelle/0017/merged.dd --db --fall DFIR-2026-0017 --als mia -o report.json
```

`evidence hinzu` hasht die Datei (SHA-256, BLAKE3, bei E01 Abgleich mit
MD5/SHA-1 der Akquise) und erkennt die Art am Format: E01, Rohimage (mit
Partitionstabelle oder Volume), pcap und pcapng; sonst `other`, mit
`--art` (z. B. `memory_dump`, `log_bundle`) zu setzen. Nicht unterstützte
Arten werden registriert und gehasht (`unsupported_format`). Eine
`bdp.info` daneben steht in den Metadaten. Eine Analyse mit `--fall` und
`--als` läuft als dieses Konto; Anmeldung, Fall und `analysis.start` werden
vor dem Image-Hash geprüft, eine schon registrierte Evidence mit gleichem
SHA-256 wird wiederverwendet. `--db` geht auch ohne `--modell`.

Statt der Umgebungsvariablen genügt eine `stratum.toml` (gesucht in
`STRATUM_KONFIG`, `./stratum.toml`, `~/.config/stratum/stratum.toml`,
`/etc/stratum/stratum.toml`; Umgebungsvariablen gehen vor):

```toml
[datenbank]
url = "postgres://stratum@127.0.0.1:5432/stratum"
passwort_datei = ".stratum_db_passwort"   # relativ zur Konfigurationsdatei

[konto]
name = "mia"                              # Vorgabe für --als
```

`stratum konfig` zeigt, welche Datei und welche Werte gelten.

Analysen lassen sich als Jobs in die Warteschlange stellen; ein Worker
führt sie im Namen dessen aus, der sie eingereiht hat (Rechte werden beim
Einreihen und beim Start geprüft):

```sh
stratum job analyse DFIR-2026-0017 merged.dd --katalog --als mia
stratum worker                       # läuft, bis er beendet wird
stratum job liste --fall DFIR-2026-0017 --als mia
stratum job zeigen <JOB-ID> --als mia
stratum job abbrechen <JOB-ID> --als mia
```

Die Warteschlange liegt in PostgreSQL (`FOR UPDATE SKIP LOCKED`), es läuft
höchstens eine Analyse zugleich. Der Worker schreibt höchstens einmal je
Sekunde Fortschritt (Phase, Stand je Phase, letzte Meldung) in den Job;
das ist zugleich sein Lebenszeichen. Ein Job ohne Lebenszeichen seit fünf
Minuten gilt als verwaist und wird beim nächsten Holen als fehlgeschlagen
beendet. Ein Abbruch greift bei wartenden Jobs sofort, bei laufenden vor
dem nächsten Schritt bzw. Analyzer; der Analyselauf endet dann als
`cancelled`. Report und Seitendateien liegen in `<Ausgabe>/<Job-ID>/`
(`[jobs] ausgabe` in `stratum.toml`, `STRATUM_JOB_AUSGABE` oder
`--ausgabe`). Jobs nehmen keine Geheimnisse an (DPAPI- oder
Firefox-Passwörter); solche Analysen laufen weiter direkt über die
Kommandozeile.

### HTTP-API

`stratum server` stellt die API unter `/api/v1` bereit (Axum), standardmäßig
nur auf `127.0.0.1:8080`; eine andere Adresse verlangt `--nicht-nur-lokal`,
da die API ohne TLS läuft. Mit `--worker` läuft ein Worker im selben
Prozess. Strg+C beendet den Server; ein laufender Job wird dabei
abgebrochen (auch mitten im Image-Hash) und als `cancelled` beendet.

Anmeldung mit `POST /api/v1/sitzung`, entweder mit JSON `{"name",
"passwort"}` oder per HTTP-Basic (`curl -u mia -c cookies.txt -X POST …`
fragt das Passwort verdeckt ab); die Antwort
enthält ein Token und setzt es als HttpOnly-Cookie `stratum_sitzung`. Jede
weitere Anfrage braucht das Cookie oder `Authorization: Bearer <Token>`.
Die Datenbank kennt nur den SHA-256 des Tokens; eine Sitzung endet mit
`DELETE /api/v1/sitzung`, nach 12 Stunden oder nach einer Stunde ohne
Anfrage. Rechte und Audit gelten wie bei der Kommandozeile.

| Methode und Pfad | Zweck |
|---|---|
| `POST`, `DELETE /api/v1/sitzung` | anmelden, abmelden |
| `POST /api/v1/registrierung` | Konto registrieren (wartet auf Freigabe) |
| `POST /api/v1/ich/passwort` | eigenes Passwort ändern |
| `GET /api/v1/konten`, `GET /api/v1/rollen` | Konten und Rollen (Superadmin) |
| `POST /api/v1/konten/{id}/freigeben`, `…/ablehnen`, `…/sperren`, `…/passwort`, `…/superadmin`; `PUT …/rollen` | Konten verwalten (Superadmin) |
| `GET /api/v1/faelle/{nummer}/ordner?pfad=` | Fallordner zur Auswahl beim Import |
| `GET /api/v1/ich` | eigenes Konto und Rechte |
| `GET /api/v1/rechte` | Katalog der Berechtigungen |
| `GET`, `POST /api/v1/faelle` | Fälle auflisten, anlegen |
| `GET /api/v1/faelle/{nummer}` | Fall mit Evidence |
| `POST /api/v1/faelle/{nummer}/evidence` | Evidence aus dem Fallordner importieren (`{"datei", "name", "rolle", "art"}`), als Job |
| `POST /api/v1/faelle/{nummer}/analysen` | Analyse als Job (`{"evidence", "optionen"}`) |
| `PUT /api/v1/faelle/{nummer}` | Titel, Beschreibung, Fallordner, Einstufung und Status ändern (`case.edit`) |
| `POST /api/v1/evidence/{id}/dateien/{volume}/{record}/ips` | IP-Literale im Dateiinhalt suchen, mit logischen Bytepositionen (`search.run`, `file.view`) |
| `GET /api/v1/jobs?fall=` | Jobs |
| `GET`, `DELETE /api/v1/jobs/{id}` | Job ansehen, abbrechen |
| `GET /api/v1/jobs/{id}/fortschritt` | Fortschritt als Server-Sent Events |
| `GET /api/v1/faelle/{nummer}/zeitachse?von=&bis=&art=&entitaet=&evidence=&suche=&nach=&anzahl=` | Ereignisse nach Zeit |
| `GET /api/v1/faelle/{nummer}/zeitachse/arten` | Ereignisarten mit Anzahl |
| `GET /api/v1/faelle/{nummer}/entitaeten?art=&suche=&nach=&anzahl=` | Entitäten |
| `GET /api/v1/entitaeten/{id}?klartext=` | Entität mit Beziehungen und Ereignissen |
| `GET /api/v1/evidence/{id}/volumes` | Volumes im Dateikatalog |
| `GET /api/v1/evidence/{id}/dateien?volume=&verzeichnis=&nach=&anzahl=` | Inhalt eines Verzeichnisses |
| `GET /api/v1/artefakte/{id}/rohfund?klartext=` | Rohfund eines Artefakts aus dem Report |
| `GET /api/v1/evidence/{id}/dateien/{volume}/{mft}` | Katalogeintrag (alle Namen bei Hardlinks) |
| `GET …/dateien/{volume}/{mft}/inhalt?offset=&laenge=` | bis 64 KiB Inhalt (Hex-Ansicht) |
| `POST …/dateien/{volume}/{mft}/hash` | SHA-256 und BLAKE3, SHA-256 in den Katalog |
| `GET …/dateien/{volume}/{mft}/export` | Inhalt als Download (`file.extract`) |
| `GET /api/v1/ereignisse/{id}` | Ereignis mit Beteiligten und Herkunft |
| `GET`, `POST /api/v1/faelle/{nummer}/warroom` | War Room lesen, Notiz anhängen |
| `GET /api/v1/audit?fall=&anzahl=` | Audit lesen |
| `POST /api/v1/audit/pruefen` | Audit-Kette nachrechnen |

Der Import über die API nimmt nur Dateien aus dem Fallordner (`ordner`
beim Anlegen des Falls), relativ zu ihm oder absolut; Pfade werden
aufgelöst, ein symbolischer Link oder `..` nach draußen wird abgelehnt.
Er braucht `evidence.import`, läuft als Job (Antwort 202 mit der Job-ID)
und hasht, erkennt die Art und registriert wie `evidence hinzu`; der
Worker prüft den Pfad vor dem Lesen noch einmal.

Zeitachse und Entitäten kommen seitenweise (`anzahl` bis 1000, Vorgabe
200) als `{"eintraege", "naechste"}`; `naechste` wird als `nach` der
nächsten Anfrage übergeben. `von` und `bis` sind RFC 3339, `art` eine
Liste mit Komma. Lesen verlangt `case.view` und `file.view` und steht als
`DATA_VIEW` im Audit. Geheime Werte sensibler Zugangsdaten (Passwort,
Hash, Secret, Masterkey) sind als `[maskiert]` ersetzt; `klartext=true`
verlangt zusätzlich `credential.view_sensitive`, jeder Versuch steht als
`CREDENTIAL_VIEW` im Audit, auch ein abgelehnter.

Der Dateibaum kommt aus dem Katalog (`--katalog` bzw. `"katalog": true`
beim Job): `verzeichnis` ist der MFT-Datensatz, ohne Angabe die Wurzel
(5); erst Unterverzeichnisse, dann Dateien, je nach Name, mit allen
Zeiten in voller FILETIME-Auflösung und `hat_kinder`. Abrufe stehen als
`FILE_VIEW` im Audit. Für den Rohfund merkt sich die Datenbank Pfad und
SHA-256 des Reports; vor dem Lesen wird die Datei gegen den Hash geprüft
und die Fundkennung aus dem Inhalt nachgerechnet. Passt eines nicht, kommt
409, fehlt der Report, 404. Geheimwerte der Zugangsdaten sind wie oben
maskiert.

Fehler kommen als `{"fehler": "…"}` mit 400, 401, 403, 404, 409 oder 500
(innere Fehler ohne Einzelheiten).

`konto passwort NAME` ändert ein Passwort: das eigene nach Eingabe des
bisherigen, als Superadmin das eines anderen Kontos (das es dann selbst
ersetzen muss); offene Sitzungen des
Kontos enden, im Audit steht `PASSWORD_CHANGE` (nie das Passwort).
Weitere: `konto ablehnen`, `konto sperren`, `konto dienst` (Dienstkonto
ohne Passwort), `rolle aendern` (ohne `--recht` bleiben die
Berechtigungen, mit `--recht` gelten genau die angegebenen), `rolle
loeschen`, `superadmin uebertragen`. Die Datenbank kommt wie bei `--db` aus
`STRATUM_DB_URL` und `STRATUM_DB_PASSWORT_DATEI`.

Das Audit (`audit_event`) hält fest, wer was getan hat: Fall angelegt,
Evidence registriert oder gegen ihren Hash geprüft (eine Abweichung als
`failure`), Analyse begonnen und beendet, Report erstellt, Konten,
Rollen, Anmeldungen (auch abgelehnte, mit Grund), Findings, Beziehungen.
Jedes Ereignis entsteht in derselben Transaktion wie die Aktion. Es ist
eine Hash-Kette: ein Trigger vergibt die nächste Nummer und berechnet
`SHA-256(vorheriger_hash + "\n" + nummer + "\n" + payload)` über den
gespeicherten Text `payload`. Ändern, Löschen und Leeren lehnt die Tabelle
ab. stratum arbeitet in der Datenbank als Rolle `stratum_app`, die nirgends
löschen und das Audit nicht ändern darf.

```sh
stratum --audit-pruefen
```

rechnet die ganze Kette nach (lückenlose Nummern, Vorgänger-Hash, Hash,
Spalten gleich Inhalt, Kopf gleich letztem Ereignis), gibt das Ergebnis als
JSON aus und endet mit Fehler, wenn sie nicht intakt ist. Ein Superuser der
Datenbank kann Trigger abschalten; eine Änderung findet dann das
Nachrechnen. Spätere Ausbaustufe: signierte Prüfpunkte außerhalb der
Datenbank.

### Weboberfläche

Die Oberfläche liegt in `stratum_frontend/` und wird einmal gebaut
(Node.js 20.19 oder ab 22.12, wie Vite es verlangt):

```sh
cd stratum_frontend
npm ci
npm run build
```

Im Fall sind Graph, Audit und Network enrichment erreichbar. Der Graph lädt
jeweils direkte, gespeicherte Beziehungen einer Entität. Jede Kante zeigt ihre
Ableitung und öffnet die Herkunft; Anheften, Ausblenden und Rücknahme betreffen
nur die Ansicht. Die Anzeige ist auf 120 Knoten und 240 Kanten begrenzt.
Audit zeigt Analystenaktionen zur Untersuchungszeit, getrennt von der Timeline.
Filter gelten für die geladenen Audit-Seiten; die Kettenprüfung prüft alle Fälle.

Dateien, Ereignisse, Entitäten, Beziehungen und Rohartefakte lassen sich mit
`Add to investigation` in die gemeinsame Fallmerkliste aufnehmen. Unter
`Investigation selection` stehen Notizen, Prüfstatus und Links zurück zur Quelle.
`Reviewed` ist eine Analystenangabe, kein bestätigtes Finding. Die Quelle bleibt
unverändert. Entfernen betrifft nur die Liste; Wiederaufnahme erhält ID und Notiz.
Änderungen stehen mit vorherigem und neuem Stand im Audit. Schreiben braucht
`bookmark.edit`, Lesen `case.view` und `file.view`. Bestehende Rollen erhalten das
neue Recht erst durch ausdrückliche Vergabe in der Administration.

Unter `Reconstruction` lassen sich eingehende Angreifer-Requests und ausgehende
verdächtige Verbindungen als Offline-HTTP-Versuche nachstellen. Methode, Header,
UTF-8-Body, Quellenverweis und Hypothese werden gespeichert. Der simulierte Server
antwortet mit einem ausdrücklich vorgegebenen Status und Body. Das Ergebnis ist
`Reconstructed`: kein Nachweis für Exploitation, Persistenz oder den damaligen
Serverzustand. HTTPS-URLs werden nur in ihrer HTTP-Semantik nachgebildet, ohne TLS.
Webanwendungen, Datenbanken, PCAP-Replay und rekonstruierte Systemkopien folgen
als eigene Lab-Umgebungen. Authentifizierungsheader und Cookies sind in diesem
ersten Simulator nicht unterstützt; synthetische Werte verwenden.

Der HTTP-Runner liegt in `stratum_lab/` und läuft als eigener Prozess in einem
kurzlebigen Container. Netzwerk `none`, read-only Root-Dateisystem, unprivilegierter
Benutzer, keine Linux-Capabilities, kein Zugriff auf Evidence oder Host-Verzeichnisse.
128 MiB RAM, eine CPU, höchstens 32 Prozesse und begrenzte Ein-/Ausgabe.
Die HTTP-Ausführung ist auf 30 Sekunden begrenzt; Vorbereitung und Bereinigung
haben zusätzliche eigene Zeitlimits. Internetzugriff, Redirect-Folgen
und ein unisolierter Fallback sind nicht vorgesehen. Die Runtime wird über den
HTTP-Lab-Connector angesprochen. Container teilen den Kernel der Lab-VM; dies ist
keine Umgebung zum Ausführen von Schadsoftware. Der Worker braucht Zugriff auf
das lokale Docker und das zuvor gebaute Image:

```sh
docker build --pull -t stratum-http-lab:v1 stratum_lab
cargo test -p stratum-connectors --test http_lab -- --ignored --nocapture
```

Der Linux-Test erwartet einen echten isolierten HTTP-Austausch mit Status 403,
ursprünglichem Host `web01.invalid` und tatsächlichem Peer `127.0.0.1`. Das Image
wird vor jeder Ausführung auf seine lokale SHA-256-ID festgelegt; ID und Runtime
stehen im Ergebnis. Automatisches Nachladen beim Versuch ist gesperrt. Fehlendes
Docker, Image oder Isolation beendet den Job mit einem Fehler.

Die Protokolltests ohne Docker verwenden ausschließlich synthetische Loopback-
Verbindungen und prüfen keine Containerisolation:

```sh
python3 -B -m unittest discover -s stratum_lab/tests -v
```

Anlegen braucht `case.view`, `file.view`, `analysis.start` und `connector.use`.
Lesen der Requests/Responses braucht zusätzlich zu `case.view` auch `file.view`,
selbst über Jobliste und Ereignisstrom. Die ursprüngliche Quelle muss zum selben
Fall gehören. Replay-Anforderung, Ausführungsbeginn und Ergebnis stehen im Audit;
die Investigation-Timeline wird nicht durch simulierte Ereignisse erweitert.

In den Explorer-Dateidetails lässt sich ein lokaler YARA-Scan einreihen. Der
Linux-Worker benötigt `/usr/bin/yara` (Version 4.5 oder neuer innerhalb Version 4)
und `/usr/bin/prlimit`. Regeltext und SHA-256 der Regeln bleiben im Job erhalten.
`include` ist ausgeschlossen, auch als Wort in Kommentaren oder Strings. Es wird
nur die gewählte Datei gelesen, ohne Datei- oder Image-Hashing. Limits: 256 MiB
Datei, 1 GiB Adressraum des YARA-Prozesses, 60 CPU-/Scansekunden, 65 Sekunden
Gesamtzeit des Prozesses, 1 MiB pro Ausgabekanal und 500 zutreffende Regeln.
Match-Offsets sind logische Dateioffsets; die gespeicherte Matchlänge kann kürzer
als das gesamte Match sein. Treffer sind Indikatoren, keine Malware-Bewertung.
Die private Arbeitskopie wird nach dem Job entfernt. Diese Prozessgrenzen sind
keine Sandbox für die Ausführung von Malware; Dateiinhalte werden nie gestartet.
CLI-Ausgabe und Optionen folgen der [YARA-Dokumentation](https://yara.readthedocs.io/en/latest/commandline.html).

Network enrichment benötigt `connector.use` und einen Linux-Worker mit
`/usr/bin/nslookup` und optional `/usr/bin/whois`. Die ausgewählten DNS-/WHOIS-
Abfragen laufen als abbrechbarer Job. HTTP(S)-URLs werden auf ihren Host reduziert,
Pfade werden nicht abgerufen; URLs mit Zugangsdaten sind unzulässig. Toolversion,
Abfragezeit und Antworten bleiben im Ergebnis, begrenzt auf 1 MiB je Ausgabekanal
und 20 Sekunden je Abfrage. Einzelne Fehler
werden getrennt ausgewiesen. Die Abfragen senden den Host an den Resolver bzw.
WHOIS-Dienst, erst nach bewusstem Einreihen des Jobs. Antworten sind heutige externe
Anreicherung und belegen keine historische Auflösung oder Kommunikation.

`stratum server` liefert danach `stratum_frontend/dist` unter
`http://127.0.0.1:8080/` aus (anderer Ort mit `--oberflaeche`,
`[server] oberflaeche` in `stratum.toml` oder `STRATUM_OBERFLAECHE`).
Angemeldet wird mit denselben Konten wie in der Kommandozeile; die Sitzung
steckt in einem HttpOnly-Cookie.

Beim ersten Start auf einer leeren Datenbank legt `stratum server` den
einzigen Superadmin `superadmin` mit dem Startpasswort `superadmin` an.
Nach der ersten Anmeldung muss es ersetzt werden (mindestens 12 Zeichen);
bis dahin lehnt die API alles andere ab. Es gibt immer genau einen
Superadmin; er kann das Recht an ein anderes Konto übergeben (`stratum
superadmin uebertragen NAME` oder in der Administration). Neue Konten
registrieren sich auf der Anmeldeseite unter "Create account" und warten,
bis der Superadmin sie unter Administration mit Rollen freigibt. Setzt er
ein Passwort zurück, muss das Konto es bei der nächsten Anmeldung selbst
ersetzen. Evidence wird aus dem Fallordner auf dem Server importiert, nicht
über den Browser hochgeladen: "Add Evidence" zeigt den Ordner zum
Auswählen.

Ansichten je Fall: Overview, War Room (Notizen und Systemeinträge zu
Jobs und Exporten, nur anhängbar), Evidence (Import, Analyse, Details),
Explorer (Verzeichnisbaum und Dateien aus dem Katalog; im Drawer
Zeitstempel SI und FN, NTFS-Angaben, Hex und Strings, Hash, Export mit
`file.extract`), Timeline (Filter nach Evidence, Zeitraum, Art, Entität
und Text; Ereignis mit Herkunft und Rohfund) und Entities.

Die Oberfläche ist ein Arbeitsplatz mit festen Zonen: Topbar (Fall,
Suche, Jobs, Benachrichtigungen, Integrität der Evidence, Konto), Sidebar
(global und je Fall, einklappbar), Workspace und Context Drawer rechts.
Details öffnen im Drawer, ohne die Ansicht zu verlassen; der Drawer steht
in der Adresse (`?detail=evidence:<id>`), Ansichten sind damit teilbar.
Formulare wie Analyse und Import erscheinen im Workspace statt in
Dialogen. Beschriftungen sind englisch, Zeiten immer UTC. Ansichten, die
noch kein Backend haben (Findings, Playbooks, Threat Intelligence …), stehen
gesperrt in der Navigation und nennen ihre Ausbaustufe.

| Taste | Wirkung |
|---|---|
| `⌘K` bzw. `Ctrl+K`, `/` | Command Palette |
| `G` dann `C`, `O`, `E` | Cases, Overview, Evidence |
| `Esc` | Drawer schließen |
| `J`/`K`, Pfeiltasten, `Enter` | Zeile wählen, öffnen |
| `[` | Sidebar ein- und ausklappen |

`/dev/design-system` zeigt alle Bausteine (Tokens, Buttons, Eingaben,
Badges, Tabelle, Drawer, Palette …) mit Beispielwerten. Die
TypeScript-Typen der Modellobjekte werden aus `stratum_model` erzeugt
(`npm run typen`, über `ts-rs` hinter dem Feature `ts`) und liegen unter
`src/lib/api/model/`; sie werden nicht von Hand geändert. Für die
Entwicklung startet `npm run dev` einen Vite-Server, der `/api` an
`127.0.0.1:8080` weiterreicht.

## E01-Images

stratum liest Expert-Witness-Images (EWF-E01, von EnCase 1 bis 7, FTK Imager,
linen und libewf) mit einem eigenen Leser (Crate `ewf`), ohne sie vorher zu
entpacken oder einzuhängen. Weitere Segmente (`.E02` ... `.E99`, `.EAA` ...)
werden neben der ersten Datei gefunden. Alle Analysen laufen auf E01 genauso
wie auf Rohimages; Offsets im Report bezeichnen die Mediendaten.

Jeder Chunk wird beim Lesen geprüft (zlib bzw. Adler-32). Ein beschädigter
Chunk führt zu einem Fehler an genau dieser Stelle, nie zu stillschweigend
eingesetzten Nullen; das Hashing bricht dann ab. Im Report stehen unter
`image.ewf` die Segmentdateien, Chunk- und Sektorgröße, die Akquisedaten
(Fallnummer, Bearbeiter, Beschreibung, Notizen, Programm, Akquisezeit) und
die bei der Akquise gespeicherten Hashes. MD5 und SHA-1 werden im selben
Durchlauf wie SHA-256 und BLAKE3 über die gelesenen Mediendaten gebildet und
verglichen (`md5_stimmt`, `sha1_stimmt`); eine Abweichung erscheint als
Warnung. Die Akquisezeit wird nur umgerechnet, wenn sie als POSIX-Zeit
vorliegt; die ältere EnCase-Form ohne Zeitzone bleibt unverändert.

Geprüft gegen libewf 20230212 (`ewfexport`, `ewfinfo`) an den E01-Dateien
aus den dfvfs-Testdaten und an mit `ewfacquire` erzeugten Varianten (EnCase 1,
5, 6, 7, FTK Imager, linen 6, mehrteilig, unkomprimiert, 128 Sektoren je
Chunk): gleiche Mediendaten, gleicher Akquise-MD5, und die vollständige
Analyse liefert dieselben Funde wie auf dem Rohimage. Nicht unterstützt und
als solches gemeldet: EWF2 (`.Ex01`) und logische Images (`.L01`).

## Schattenkopien (VSS)

stratum liest Volume Shadow Copies mit einem eigenen Parser (Crate `vss`)
nach der Formatbeschreibung von libvshadow. Ein Snapshot entsteht, indem die
Stores vom jüngsten bis zum gewünschten über das aktuelle Volume gelegt
werden; dabei werden Forwarder, Overlays (512-Byte-Abschnitte) und die
Belegungs-Bitmaps berücksichtigt. Für jede Stelle eines Snapshots lässt sich
angeben, ob die Bytes aus einer Store-Kopie oder aus dem aktuellen Volume
stammen und wo sie physisch liegen.

Je Schattenkopie entsteht ein Fund mit Store-, Schattenkopie- und
Satzkennung, Erstellungszeit, Attributen, Zahl der Blockdeskriptoren und der
Dateien. Die Nummer `VSS#n` zählt nach Erstellungszeit, 1 ist die älteste.
Registry-basierte Analyzer laufen auch auf den Snapshots.

**Dateiabgleich.** Jeder Snapshot wird durchlaufen und mit dem Live-Stand
verglichen. Eine Datei gilt nur dann als unverändert, wenn ihr Inhalt
nachweislich gleich ist: gleiche Datenläufe, und kein Block dieser Läufe wurde
seit dem Snapshot in einen Store kopiert; andernfalls werden die Bytes des
Blocks verglichen. Residente Inhalte werden direkt verglichen, bei
verschiedenen Datenläufen oder komprimierten Strömen der ganze Inhalt (bis
256 MiB, darüber `nicht_pruefbar`). Je abweichender Datei entsteht ein Fund
(`art` = `vss_datei`) mit `status` (`nur_im_snapshot`, `inhalt_abweichend`,
`nicht_pruefbar`), Metadaten aus Snapshot und Live-Stand und dem Image-Offset
des MFT-Datensatzes im Snapshot. NTFS-Metadateien sind mit `ntfs_metadatei`
gekennzeichnet. Verglichen wird der unbenannte Datenstrom.

**Artefakte aus Snapshots.** Die dateibasierten Analyzer (Ereignisprotokolle,
Prefetch, LNK, Jump Lists, Papierkorb, Browser, PowerShell, Aufgaben und
Autostart, Tor, DPAPI, ActivitiesCache, SRUM, WebCache) laufen zusätzlich auf
den abweichenden Dateien jedes Snapshots. Unveränderte Dateien werden nicht
erneut ausgewertet. Aus einer geänderten Datei können Funde stammen, die auch
im Live-Stand vorkommen (etwa ältere Einträge eines weitergeschriebenen
Protokolls); sie sind über die Herkunft unterscheidbar. Solche Funde tragen
`herkunft` (`VSS#n`), `vss_erstellt_utc` und `vss_volume_offset`; ihre
Image-Offsets sind über die Schattenkopie auf die physische Stelle der Bytes
umgerechnet.

Geprüft gegen libvshadow am öffentlichen Testimage `vss.raw` aus dfvfs (zwei
Stores): beide Snapshots Block für Block identisch. Der Dateiabgleich stimmt
dort mit einem vollständigen Inhaltsvergleich aller Dateien überein. Das
Testimage enthält keine später gelöschten Dateien und keine Artefakte; diese
Fälle sind nur mit synthetischen Daten geprüft. Die zuvor genutzte Crate
`vshadow` wich dort in 11 bzw. 75 von 5.052 Blöcken ab und stand unter
AGPL-3.0; sie wird nicht mehr verwendet.

## USB-Zeitpunkte

USBSTOR-Geräte erhalten Zeitpunkte aus den Standardwerten unter
`Properties\{83da6326-97a6-4088-9453-a1923f573b29}` im aktiven ControlSet:

| Property | Zeitfeld | Bedeutung |
|---|---|---|
| `0064` | `installation` | Installation, auch nach Treiberaktualisierung |
| `0065` | `erste_installation` | Erste Installation dieser Geräteinstanz |
| `0066` | `letzte_verbindung` | Letzte Verbindung |
| `0067` | `letztes_trennen` | Letztes Trennen |

Die Zuordnung folgt [Microsofts devpkey.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/devpkey.h).
RegRipper `usbstor` v.20200515 vertauscht die Beschriftungen von `0064` und
`0065`; bei unterschiedlichen Werten ist das beim Vergleich zu berücksichtigen.

Je Zeitfeld stehen `*_utc` (100-ns-Präzision), `*_unix` (ganze Sekunden) und
`*_filetime` (Rohwert) im Fund. FILETIME ist bereits UTC und benötigt keine
Umrechnung mit der Zeitzone des untersuchten Systems oder des Analyse-Rechners.
Die vier Zeiten erscheinen als getrennte Ereignisse in der Timeline.
`*_quelle` nennt den Property-Pfad einschließlich Standardwert, `*_hive_offset`
die vk-Zelle und `*_key_hive_offset` die nk-Zelle in der SYSTEM-Hive-Datei,
jeweils einschließlich des Zellgrößenfelds. `hive_offset` bezeichnet die
Geräteinstanz, `volume_offset` das zugehörige Volume im Image. Diese
Hive-Offsets sind keine physischen Image-Offsets.

`*_status` unterscheidet `vorhanden`, `nicht_vorhanden`, `nicht_gesetzt`
(Nullwert) und `nicht_lesbar` (zusätzlich eine Warnung). Unterstützt ist das
gegen Windows 11 geprüfte Layout mit acht Byte und Property-Typ `0xffff0010`.
Andere Typen oder Längen werden nicht als Zeit interpretiert. Ältere Layouts
mit anderen Schlüsselpfaden sind nicht abgedeckt. Schlüsseländerungszeiten
dienen nicht als Ersatz für fehlende Gerätezeitpunkte. Ein fehlender
Trennzeitpunkt belegt nicht, dass das Gerät noch verbunden war.

## PowerShell-Verlauf und Ereignisquellen

Der PowerShell-Analyzer liest `ConsoleHost_history.txt` sowie weitere
`*_history.txt` unter PSReadLine-Verzeichnissen über den vorhandenen NTFS-Index.
Er erfasst physische UTF-8-Zeilen, Profilzuordnung aus dem Pfad, Zeilennummer,
Byte-Offset innerhalb der Datei, MFT-Nummer und Volume-Offset. Ein Verlaufseintrag
belegt allein weder die Ausführung noch ihren Zeitpunkt oder Erfolg. Mehrzeilige
Eingaben bleiben als einzelne Quellzeilen mit Fortsetzungsmarkierung erhalten.
Abweichende, frei konfigurierte Dateinamen werden nicht automatisch erkannt.

Grenzen: 16 MiB je Verlaufsdatei, 50.000 physische Zeilen, 64 KiB je Zeile.
Überschreitungen und ungültiges UTF-8 erscheinen als Warnungen. Verläufe, die
in einer Schattenkopie vom Live-Stand abweichen, werden zusätzlich ausgewertet
(siehe Schattenkopien).
Die Standardpfade beschreibt die [PSReadLine-Dokumentation](https://learn.microsoft.com/en-us/powershell/module/psreadline/set-psreadlineoption).

Die Timeline enthält alle unterstützten Zeitfelder eines Funds. `finding_index`
verweist auf den Index im `findings`-Array desselben Reports; `time_key` benennt
das ursprüngliche Zeitfeld. Diese Referenz gilt innerhalb dieses Reports und ist
keine fallübergreifende Kennung. Papierkorb-, Registry- und LNK-Zeiten bleiben
als unterschiedliche Ereignisarten erhalten. Zeitliche Nähe allein belegt
keinen ursächlichen Zusammenhang. LNK-Zielzeiten, die genau der DOS-Epoche
(1980-01-01 00:00 Ortszeit) entsprechen, sind Platzhalter ohne echte
Zeitangabe, etwa bei der Wurzel eines FAT-Laufwerks. Sie stehen als
`*_platzhalter_unix` im Fund und nicht in der Timeline.

Dienste mit ImagePath und geplante Aufgaben bleiben auch bei gewöhnlichem
Programmpfad erhalten. `auffaellig` ist eine Heuristik für die Sichtung und
keine Aussage über Schadsoftware; `auffaellig_grund` nennt den Anlass.

- `pfad_status`: `gewoehnlich` unterhalb des Windows-Verzeichnisses oder von
  `Program Files`, `auffaellig` bei nutzerbeschreibbaren Orten (Users, AppData,
  Temp, ProgramData, Windows\Temp), UNC-Pfaden, `..` oder Orten außerhalb der
  Standardverzeichnisse, `unbestimmt` bei Programmen ohne Verzeichnis oder
  unbekannten Umgebungsvariablen. Umgebungsvariablen wie `%SystemRoot%` und
  `%ProgramFiles%` sowie `\??\`-Präfixe werden vorher aufgelöst.
- Dienste: ein Systemwerkzeug (cmd, PowerShell, rundll32, mshta usw.) als
  ImagePath gilt immer als auffällig. `unquotierter_pfad` kennzeichnet
  unquotierte Pfade mit Leerzeichen.
- Aufgaben: alle Exec- und ComHandler-Aktionen werden erfasst (`aktion`,
  `weitere_befehle`, `com_handler`). ComHandler allein sind nicht auffällig.
  Systemwerkzeuge sind in Windows-Aufgaben üblich und werden nur mit
  auffälligen Argumenten markiert (URL, UNC, nutzerbeschreibbarer Pfad,
  kodierter oder versteckter Aufruf).

## Weiterer Ausbau

Geplant, noch nicht implementiert:

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

`tool.revision` nennt den Git-Commit, aus dem das Binary gebaut wurde, und
`tool.revision_geaendert`, ob dabei nicht committete Änderungen vorlagen. Dieselbe
Angabe zeigt `stratum --version`. Unter `analyzers` steht je Analyzer, wie viele
Funde und Warnungen er geliefert hat und wie lange er lief; null Funde heißt nur,
dass dieser Analyzer nichts gemeldet hat, Lesehindernisse stehen in den
Warnungen. Jeder Fund trägt eine `id` aus den ersten 16 Hexzeichen eines
SHA-256 über seinen Inhalt. Dasselbe Image ergibt in jedem Lauf dieselben
Kennungen, so lassen sich Funde über Läufe und Werkzeugstände hinweg
vergleichen; die Timeline verweist mit `finding_id` darauf.

Für die Weiterverarbeitung in Cortex XSOAR liegt unter `stratum_backend/xsoar/` eine Vorlage
(Automation, Playbook), die den JSON-Report einliest, `.onion`-Adressen als
Indikatoren anlegt und den Incident bei Belegen für einen Hidden Service
hochstuft.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Jeder Parser hat Unit-Tests gegen synthetische Fixtures und mindestens einen Integrationstest. Die Krypto-Bausteine der Konten-Extraktion sind gegen veröffentlichte Testvektoren geprüft. Die abschliessende Bestätigung der Konten gegen echte Hives (Vergleich mit `samdump2` oder `secretsdump.py`) gehört auf die Analyse-Umgebung.

Die Fuzz-Targets liegen unter `stratum_backend/fuzz/` und brauchen eine
nightly-Toolchain:

```sh
cargo install cargo-fuzz
cd stratum_backend
cargo +nightly fuzz run hive
```

Der PowerShell-Test gegen ein erzeugtes NTFS-Volume benötigt `mkntfs` und
`ntfscp`. Er ist explizit auszuführen und schlägt bei fehlenden Werkzeugen fehl:

```sh
cargo test -p stratum-analysis --test powershell_ntfs -- --ignored
```

Der zusätzliche Mini-Image-Test prüft read-only Zugriff, Dateipositionen und
Serialisierung ohne externe Werkzeuge. Das Fuzz-Target heißt `powershell`.

Einige Tests prüfen gegen echte Daten, die nicht im Repository liegen. Sie
laufen mit `--ignored` und brauchen Verzeichnisse beziehungsweise Dateien über
Umgebungsvariablen: `STRATUM_USB_REFERENCE_DIR` (SYSTEM-Hive und
WinScope-Report), `STRATUM_EVTX_REFERENCE` (eine `.evtx`-Datei) und
`STRATUM_HIVELOG_REFERENCE` (Hives mit ihren `.LOG1`/`.LOG2`) und
`STRATUM_SHELLITEM_REFERENCE` (LNK-Dateien, RegRipper-Ausgaben
`shellbags` und `userassist` sowie eine `ActivitiesCache.db`) und
`STRATUM_ESE_REFERENCE` (`SRUDB.dat`, `WebCacheV01.dat` und die
dissect-Referenzen als JSON), `STRATUM_VSS_REFERENCE` (`vss.raw` aus den
dfvfs-Testdaten und die libvshadow-Referenz als JSON) und
`STRATUM_EWF_REFERENCE` (E01-Testimages aus den dfvfs-Testdaten und mit
`ewfacquire` erzeugte Varianten).

## Lizenz

Dieses Projekt steht unter der [MIT License](LICENSE) © 2025 [yalmn](https://github.com/yalmn/).
