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
| Artefakt-Domänen | Autostart, USB, Programmausführung (Amcache, Shimcache, Prefetch, BAM/DAM), Benutzeraktivität (UserAssist, ShellBags, ActivitiesCache, TypedURLs, TypedPaths, RunMRU, WordWheelQuery, RecentDocs), Ressourcennutzung (SRUM), EventLog, Browser-Verlauf (auch WebCache) und -Passwörter, LSA/DCC2, DPAPI, Tor, Volume Shadow Copies |
| Keyword-Suche | Begriffe aus einer Tabelle, in ASCII und UTF-16LE, Zugangsdaten als Paar (Benutzer- und Passwort-Feld in geringem Abstand), validierte v3-Onion-Adressen |

Die Begriffe für die Suche stehen bewusst nicht im Code, sondern in einer pro Fall gepflegten und versionierten TOML-Tabelle. So bleibt nachvollziehbar, wonach gesucht wurde, und das Rauschen lässt sich pro Fall über die aktiven Kategorien steuern. Eine Beispieltabelle liegt unter `search/examples/begriffe.toml`.

## Aufbau

Cargo-Workspace aus mehreren Crates:

```
mmap/      Read-only Memory-Mapping (einzige unsafe-Grenze, gekapselt)
core/      Image-IO, Hashing, Partitionen, Analyzer-Trait
registry/  Parser für Windows-Registry-Hives (regf) und ihre Transaktionslogs
ese/       Parser für ESE-Datenbanken (SRUM, WebCache)
vss/       Parser für Volume Shadow Copies
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
| `--dump-record <volume_offset> <mft> <ziel>` | eine Datei über Volume-Offset und MFT-Nummer extrahieren (Werte aus dem Katalog) |
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
Ereignisse (Anmeldungen, Konten, Dienste, Protokolllöschung, RDP). Jeder Fund
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

## Schattenkopien (VSS)

stratum liest Volume Shadow Copies mit einem eigenen Parser (Crate `vss`)
nach der Formatbeschreibung von libvshadow. Ein Snapshot entsteht, indem die
Stores vom jüngsten bis zum gewünschten über das aktuelle Volume gelegt
werden; dabei werden Forwarder, Overlays (512-Byte-Abschnitte) und die
Belegungs-Bitmaps berücksichtigt. Für jede Stelle eines Snapshots lässt sich
angeben, ob die Bytes aus einer Store-Kopie oder aus dem aktuellen Volume
stammen und wo sie physisch liegen.

Je Schattenkopie entsteht ein Fund mit Store-, Schattenkopie- und
Satzkennung, Erstellungszeit, Attributen und Zahl der Blockdeskriptoren. Die
Nummer `VSS#n` zählt nach Erstellungszeit, 1 ist die älteste. Registry-
basierte Analyzer laufen auch auf den Snapshots.

Geprüft gegen libvshadow am öffentlichen Testimage `vss.raw` aus dfvfs (zwei
Stores): beide Snapshots Block für Block identisch. Die zuvor genutzte Crate
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
Überschreitungen und ungültiges UTF-8 erscheinen als Warnungen. Der Analyzer
arbeitet derzeit auf den indizierten Live-NTFS-Volumes, nicht auf Schattenkopien.
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

`tool.revision` nennt den Git-Commit, aus dem das Binary gebaut wurde, und
`tool.revision_geaendert`, ob dabei nicht committete Änderungen vorlagen. Dieselbe
Angabe zeigt `stratum --version`. Unter `analyzers` steht je Analyzer, wie viele
Funde und Warnungen er geliefert hat und wie lange er lief; null Funde heißt nur,
dass dieser Analyzer nichts gemeldet hat, Lesehindernisse stehen in den
Warnungen. Jeder Fund trägt eine `id` aus den ersten 16 Hexzeichen eines
SHA-256 über seinen Inhalt. Dasselbe Image ergibt in jedem Lauf dieselben
Kennungen, so lassen sich Funde über Läufe und Werkzeugstände hinweg
vergleichen; die Timeline verweist mit `finding_id` darauf.

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

Einige Tests prüfen gegen echte Daten, die nicht im Repository liegen. Sie
laufen mit `--ignored` und brauchen Verzeichnisse beziehungsweise Dateien über
Umgebungsvariablen: `STRATUM_USB_REFERENCE_DIR` (SYSTEM-Hive und
WinScope-Report), `STRATUM_EVTX_REFERENCE` (eine `.evtx`-Datei) und
`STRATUM_HIVELOG_REFERENCE` (Hives mit ihren `.LOG1`/`.LOG2`) und
`STRATUM_SHELLITEM_REFERENCE` (LNK-Dateien, RegRipper-Ausgaben
`shellbags` und `userassist` sowie eine `ActivitiesCache.db`) und
`STRATUM_ESE_REFERENCE` (`SRUDB.dat`, `WebCacheV01.dat` und die
dissect-Referenzen als JSON) und `STRATUM_VSS_REFERENCE` (`vss.raw` aus den
dfvfs-Testdaten und die libvshadow-Referenz als JSON).

## Lizenz

Dieses Projekt steht unter der [MIT License](LICENSE) © 2025 [yalmn](https://github.com/yalmn/).
