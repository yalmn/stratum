"""
XSOAR-Automation: liest einen stratum-Report (report.json) ein und macht die
Funde in XSOAR nutzbar.

Ausgaben:
- Kontext unter "Stratum" (Image, Partitionen, Konten, Funde, Zeitstrahl).
- Indikatoren für gefundene .onion-Adressen (Domain-Typ).
- eine Zusammenfassung als Markdown im War Room.

Aufruf in XSOAR (Automation, Python3):
    !StratumIngest report={{.="report.json Inhalt"}}
oder mit einer im Incident angehängten Datei über entryID.

Dieses Skript ist eine Vorlage; Feldnamen ggf. an den eigenen XSOAR-Mandanten
anpassen. Es benötigt keine externen Bibliotheken außer dem XSOAR-SDK.
"""

import json

import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore  # noqa: F401,F403


def load_report() -> dict:
    """Report aus dem Argument 'report' oder aus einer angehängten Datei lesen."""
    args = demisto.args()
    raw = args.get("report")
    if raw:
        return json.loads(raw)
    entry_id = args.get("entryID")
    if entry_id:
        path = demisto.getFilePath(entry_id)["path"]
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    raise ValueError("Weder 'report' noch 'entryID' angegeben")


def onion_indicators(findings: list) -> list:
    """.onion-Adressen aus den Tor-Funden als Domain-Indikatoren."""
    onions = set()
    for f in findings:
        if f.get("domain") == "tor":
            name = f.get("name", "")
            for token in name.replace("/", " ").split():
                if token.endswith(".onion"):
                    onions.add(token)
    return [{"type": "Domain", "value": o} for o in sorted(onions)]


def summarize(report: dict) -> str:
    img = report.get("image", {})
    windows = report.get("windows", [])
    findings = report.get("findings", [])
    by_domain: dict = {}
    for f in findings:
        by_domain[f.get("domain", "?")] = by_domain.get(f.get("domain", "?"), 0) + 1

    lines = ["## stratum Report", ""]
    lines.append(f"- Image: `{img.get('path', '?')}` ({img.get('size', 0)} Bytes)")
    if img.get("hashes"):
        lines.append(f"- SHA-256: `{img['hashes'].get('sha256', '')}`")
    lines.append(f"- Windows-Installationen: {len(windows)}")
    for w in windows:
        lines.append(
            f"  - {w.get('computer_name', '?')}: {len(w.get('accounts', []))} Konto(en)"
        )
    lines.append(f"- Funde gesamt: {len(findings)}")
    for dom, n in sorted(by_domain.items(), key=lambda x: -x[1]):
        lines.append(f"  - {dom}: {n}")
    lines.append(f"- Zeitstrahl-Ereignisse: {len(report.get('timeline', []))}")
    return "\n".join(lines)


def main() -> None:
    try:
        report = load_report()
    except Exception as exc:  # noqa: BLE001
        return_error(f"stratum-Report nicht lesbar: {exc}")
        return

    findings = report.get("findings", [])
    indicators = onion_indicators(findings)
    tor_found = any(f.get("domain") == "tor" for f in findings)

    context = {
        "Stratum": {
            "Image": report.get("image", {}),
            "Partitions": report.get("partitions", {}),
            "Windows": report.get("windows", []),
            "Findings": findings,
            "Timeline": report.get("timeline", []),
            "OnionIndicators": [i["value"] for i in indicators],
            "TorHiddenServiceFound": tor_found,
        }
    }

    results = CommandResults(  # type: ignore  # noqa: F405
        readable_output=summarize(report),
        outputs=context,
        raw_response=report,
    )
    return_results(results)  # type: ignore  # noqa: F405

    # Onion-Adressen als Indikatoren anlegen.
    for ind in indicators:
        demisto.createIndicators([ind])


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
