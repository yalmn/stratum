import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  beendet,
  type AnalyseOptionen,
  type Evidence,
  type FallDetail,
  type Fortschritt,
  type Job,
  type JobStatus,
} from "../api";
import { groesse, jobArt, jobStatus, kurz, phase, zahl, zeit } from "../format";
import { useSitzung } from "../sitzung";

export function FallSeite() {
  const nummer = useParams().nummer ?? "";
  const pfad = `/faelle/${encodeURIComponent(nummer)}`;
  const fall = useQuery({ queryKey: ["fall", nummer], queryFn: () => api<FallDetail>(pfad) });

  if (fall.error) {
    return <p className="fehler">{fall.error.message}</p>;
  }
  if (!fall.data) {
    return <p className="hinweis">Lade …</p>;
  }
  const f = fall.data.fall;
  return (
    <section>
      <div className="titelzeile">
        <h1>
          {f.case_number} <span className="leise">{f.title}</span>
        </h1>
      </div>
      <nav className="reiter">
        <NavLink to="" end>
          Übersicht
        </NavLink>
      </nav>
      <Routes>
        <Route index element={<Uebersicht nummer={nummer} detail={fall.data} />} />
      </Routes>
    </section>
  );
}

function Uebersicht({ nummer, detail }: { nummer: string; detail: FallDetail }) {
  const { darf } = useSitzung();
  const f = detail.fall;
  const [analyse, setAnalyse] = useState<Evidence | null>(null);
  return (
    <>
      <dl className="angaben">
        <dt>Stand</dt>
        <dd>{f.status}</dd>
        <dt>Einstufung</dt>
        <dd>{f.classification}</dd>
        <dt>Fallordner</dt>
        <dd>{f.case_folder ?? <span className="hinweis">keiner</span>}</dd>
        <dt>Zeitzone</dt>
        <dd>{f.timezone ?? <span className="hinweis">nicht festgelegt</span>}</dd>
        <dt>Geöffnet</dt>
        <dd>{zeit(f.opened_at)}</dd>
        {f.description && (
          <>
            <dt>Beschreibung</dt>
            <dd>{f.description}</dd>
          </>
        )}
      </dl>

      <h2>Evidence</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Art</th>
            <th>Unterstützung</th>
            <th className="zahl">Größe</th>
            <th>SHA-256</th>
            <th>Rolle</th>
            <th>Registriert</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {detail.evidence.map((e) => (
            <tr key={e.id}>
              <td title={e.source_uri}>{e.name}</td>
              <td>{e.kind}</td>
              <td>{e.support}</td>
              <td className="zahl">{groesse(e.size)}</td>
              <td className="mono" title={e.sha256}>
                {kurz(e.sha256, 16)}
              </td>
              <td>{e.role}</td>
              <td className="zeit">{zeit(e.imported_at)}</td>
              <td>
                {darf("analysis.start") && (e.kind === "raw_disk_image" || e.kind === "e01_image") && (
                  <button type="button" className="klein" onClick={() => setAnalyse(e)}>
                    Analysieren
                  </button>
                )}
              </td>
            </tr>
          ))}
          {detail.evidence.length === 0 && (
            <tr>
              <td colSpan={8} className="hinweis">
                Noch keine Evidence.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {analyse && <AnalyseStarten nummer={nummer} evidence={analyse} schliessen={() => setAnalyse(null)} />}
      {darf("evidence.import") && f.case_folder && <Import nummer={nummer} ordner={f.case_folder} />}

      <h2>Jobs</h2>
      <Jobs nummer={nummer} />
    </>
  );
}

const OPTIONEN: [keyof AnalyseOptionen, string][] = [
  ["katalog", "Dateikatalog"],
  ["datei_hashes", "SHA-256 jeder Datei (liest alle Inhalte)"],
  ["mft_timeline", "MFT-Zeitachse"],
  ["usn_journal", "USN-Journal"],
  ["raw_sweep", "Ganzes Image roh nach Begriffen durchsuchen"],
  ["ohne_begriffe", "Mitgelieferte Begriffsliste nicht verwenden"],
  ["bdp", "Vermerkte bdp.info verwenden"],
];

function AnalyseStarten({
  nummer,
  evidence,
  schliessen,
}: {
  nummer: string;
  evidence: Evidence;
  schliessen: () => void;
}) {
  const client = useQueryClient();
  const starten = useMutation({
    mutationFn: (optionen: Partial<AnalyseOptionen>) =>
      api<{ job: string }>(`/faelle/${encodeURIComponent(nummer)}/analysen`, {
        methode: "POST",
        daten: { evidence: evidence.id, optionen },
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["jobs", nummer] });
      schliessen();
    },
  });
  return (
    <form
      className="kasten"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const o: Partial<AnalyseOptionen> = {};
        for (const [k] of OPTIONEN) {
          o[k] = f.get(k) === "on";
        }
        starten.mutate(o);
      }}
    >
      <h2>Analyse von {evidence.name}</h2>
      <p className="hinweis">
        Vor der Analyse wird das Image vollständig gehasht und mit dem registrierten Hash verglichen.
      </p>
      <div className="optionen">
        {OPTIONEN.map(([k, text]) => (
          <label key={k} className="haken">
            <input type="checkbox" name={k} defaultChecked={k === "katalog"} />
            {text}
          </label>
        ))}
      </div>
      <div className="aktionen">
        <button type="submit" disabled={starten.isPending}>
          Einreihen
        </button>
        <button type="button" className="leise" onClick={schliessen}>
          Abbrechen
        </button>
      </div>
      {starten.error && <p className="fehler">{starten.error.message}</p>}
    </form>
  );
}

function Import({ nummer, ordner }: { nummer: string; ordner: string }) {
  const client = useQueryClient();
  const [offen, setOffen] = useState(false);
  const importieren = useMutation({
    mutationFn: (d: Record<string, string>) =>
      api<{ job: string }>(`/faelle/${encodeURIComponent(nummer)}/evidence`, { methode: "POST", daten: d }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["jobs", nummer] });
      setOffen(false);
    },
  });
  if (!offen) {
    return (
      <p>
        <button type="button" className="leise" onClick={() => setOffen(true)}>
          Evidence aus dem Fallordner importieren
        </button>
      </p>
    );
  }
  return (
    <form
      className="kasten"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const d: Record<string, string> = {};
        for (const k of ["datei", "name", "rolle"]) {
          const v = String(f.get(k) ?? "").trim();
          if (v) {
            d[k] = v;
          }
        }
        importieren.mutate(d);
      }}
    >
      <h2>Import aus {ordner}</h2>
      <div className="raster">
        <label>
          Datei (relativ zum Fallordner)
          <input name="datei" required placeholder="images/rechner.E01" />
        </label>
        <label>
          Anzeigename
          <input name="name" />
        </label>
        <label>
          System oder Rolle
          <input name="rolle" placeholder="Webserver" />
        </label>
      </div>
      <div className="aktionen">
        <button type="submit" disabled={importieren.isPending}>
          Importieren
        </button>
        <button type="button" className="leise" onClick={() => setOffen(false)}>
          Abbrechen
        </button>
      </div>
      {importieren.error && <p className="fehler">{importieren.error.message}</p>}
    </form>
  );
}

function Jobs({ nummer }: { nummer: string }) {
  const jobs = useQuery({
    queryKey: ["jobs", nummer],
    queryFn: () => api<Job[]>(`/jobs?fall=${encodeURIComponent(nummer)}&anzahl=50`),
  });
  if (jobs.error) {
    return <p className="fehler">{jobs.error.message}</p>;
  }
  if (!jobs.data) {
    return <p className="hinweis">Lade …</p>;
  }
  if (jobs.data.length === 0) {
    return <p className="hinweis">Noch keine Jobs.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Art</th>
          <th>Stand</th>
          <th>Fortschritt</th>
          <th>Angelegt</th>
          <th>Beendet</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {jobs.data.map((j) => (
          <JobZeile key={j.id} nummer={nummer} job={j} />
        ))}
      </tbody>
    </table>
  );
}

interface Stand {
  status: JobStatus;
  progress: Fortschritt;
  error: string | null;
  result: Record<string, unknown> | null;
}

// Laufende Jobs verfolgen ihren Fortschritt über Server-Sent Events.
function JobZeile({ nummer, job }: { nummer: string; job: Job }) {
  const { darf } = useSitzung();
  const client = useQueryClient();
  const [stand, setStand] = useState<Stand>(job);

  useEffect(() => {
    if (beendet(job.status)) {
      return;
    }
    const quelle = new EventSource(`/api/v1/jobs/${job.id}/fortschritt`);
    quelle.addEventListener("stand", (e) => {
      const s = JSON.parse((e as MessageEvent<string>).data) as Stand;
      setStand(s);
      if (beendet(s.status)) {
        quelle.close();
        void client.invalidateQueries({ queryKey: ["jobs", nummer] });
        void client.invalidateQueries({ queryKey: ["fall", nummer] });
      }
    });
    // Nach dem Ende versucht EventSource sonst neu zu verbinden.
    quelle.addEventListener("fehler", () => quelle.close());
    return () => quelle.close();
  }, [job.id, job.status, nummer, client]);

  const abbrechen = useMutation({
    mutationFn: () => api<unknown>(`/jobs/${job.id}`, { methode: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["jobs", nummer] }),
  });

  return (
    <tr>
      <td>{jobArt(job.kind)}</td>
      <td className={`stand ${stand.status}`}>{jobStatus(stand.status)}</td>
      <td>
        <FortschrittAnzeige stand={stand} />
      </td>
      <td className="zeit">{zeit(job.created_at)}</td>
      <td className="zeit">{zeit(job.finished_at)}</td>
      <td>
        {!beendet(stand.status) && darf("analysis.cancel") && (
          <button
            type="button"
            className="klein leise"
            disabled={abbrechen.isPending || job.cancel_requested}
            onClick={() => abbrechen.mutate()}
          >
            Abbrechen
          </button>
        )}
      </td>
    </tr>
  );
}

function FortschrittAnzeige({ stand }: { stand: Stand }) {
  if (stand.status === "failed" || stand.status === "cancelled") {
    return <span className="fehler">{stand.error}</span>;
  }
  if (stand.status === "completed") {
    const r = stand.result ?? {};
    const teile: string[] = [];
    if (typeof r.funde === "number") {
      teile.push(`${zahl(r.funde)} Funde`);
    }
    if (typeof r.zeitstrahl === "number") {
      teile.push(`${zahl(r.zeitstrahl)} Einträge Zeitachse`);
    }
    if (typeof r.name === "string") {
      teile.push(`${r.name} ${r.neu ? "registriert" : "bestätigt"}`);
    }
    if (typeof r.sha256 === "string" || typeof r.report_sha256 === "string") {
      const h = String(r.sha256 ?? r.report_sha256);
      teile.push(`SHA-256 ${kurz(h)}`);
    }
    return <span className="hinweis">{teile.join(", ")}</span>;
  }
  const p = stand.progress;
  const aktuell = p.phase ? p.phasen?.[p.phase] : undefined;
  const anteil = aktuell && aktuell.gesamt > 0 ? Math.min(1, aktuell.erledigt / aktuell.gesamt) : null;
  return (
    <div className="fortschritt">
      {p.phase && <span>{phase(p.phase)}</span>}
      {anteil !== null && (
        <span className="balken" title={`${Math.round(anteil * 100)} %`}>
          <span style={{ width: `${anteil * 100}%` }} />
        </span>
      )}
      {anteil !== null && <span className="hinweis">{Math.round(anteil * 100)} %</span>}
      {p.meldung && <span className="hinweis">{p.meldung}</span>}
    </div>
  );
}
