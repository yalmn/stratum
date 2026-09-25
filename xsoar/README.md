# stratum in XSOAR

Anbindung des JSON-Reports an Cortex XSOAR. Die Dateien hier sind eine Vorlage
und müssen an den eigenen Mandanten angepasst werden.

## Ablauf

1. stratum läuft auf der forensischen Maschine und schreibt `report.json`
   (plus `report.json.sha256` als Prüfsummen-Beisatz):

   ```sh
   stratum merged.dd -o report.json --bdp bdp.info
   ```

2. Der Report wird an einen XSOAR-Incident angehängt (z. B. per API oder
   über ein Verzeichnis, das XSOAR überwacht).

3. Das Playbook `stratum_playbook.yml` ruft die Automation `stratum_ingest.py`
   auf. Diese liest den Report, schreibt die Funde in den Kontext unter
   `Stratum`, legt gefundene `.onion`-Adressen als Domain-Indikatoren an und
   erzeugt eine Zusammenfassung im War Room.

4. Findet der Report Belege für einen betriebenen Hidden Service
   (`Stratum.TorHiddenServiceFound`), setzt das Playbook den Schweregrad hoch.

## Dateien

- `stratum_ingest.py`: XSOAR-Automation (Python 3), liest den Report.
- `stratum_playbook.yml`: Playbook, das die Automation einbindet.

## Integrität

Vor der Verarbeitung sollte die Prüfsumme des Reports gegen die mitgelieferte
`report.json.sha256` geprüft werden, damit im Vorgang belegt ist, dass der
Report unverändert ist.
