import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Fall, type FallZeile } from "../api";
import { zeit } from "../format";
import { useSitzung } from "../sitzung";

export function Faelle() {
  const { darf } = useSitzung();
  const [neu, setNeu] = useState(false);
  const faelle = useQuery({ queryKey: ["faelle"], queryFn: () => api<FallZeile[]>("/faelle") });

  return (
    <section>
      <div className="titelzeile">
        <h1>Fälle</h1>
        {darf("case.create") && !neu && (
          <button type="button" onClick={() => setNeu(true)}>
            Neuer Fall
          </button>
        )}
      </div>
      {neu && <NeuerFall schliessen={() => setNeu(false)} />}
      {faelle.error && <p className="fehler">{faelle.error.message}</p>}
      {faelle.data && (
        <table>
          <thead>
            <tr>
              <th>Nummer</th>
              <th>Titel</th>
              <th>Stand</th>
              <th>Einstufung</th>
              <th className="zahl">Evidence</th>
              <th>Angelegt</th>
            </tr>
          </thead>
          <tbody>
            {faelle.data.map((f) => (
              <tr key={f.id}>
                <td>
                  <Link to={`/faelle/${encodeURIComponent(f.case_number)}`}>{f.case_number}</Link>
                </td>
                <td>{f.title}</td>
                <td>{f.status}</td>
                <td>{f.classification}</td>
                <td className="zahl">{f.evidence}</td>
                <td className="zeit">{zeit(f.created_at)}</td>
              </tr>
            ))}
            {faelle.data.length === 0 && (
              <tr>
                <td colSpan={6} className="hinweis">
                  Noch keine Fälle.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NeuerFall({ schliessen }: { schliessen: () => void }) {
  const client = useQueryClient();
  const anlegen = useMutation({
    mutationFn: (d: Record<string, string>) => api<Fall>("/faelle", { methode: "POST", daten: d }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["faelle"] });
      schliessen();
    },
  });
  return (
    <form
      className="kasten"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const d: Record<string, string> = {};
        for (const k of ["nummer", "titel", "ordner", "beschreibung", "zeitzone"]) {
          const v = String(f.get(k) ?? "").trim();
          if (v) {
            d[k] = v;
          }
        }
        anlegen.mutate(d);
      }}
    >
      <h2>Neuer Fall</h2>
      <div className="raster">
        <label>
          Fallnummer
          <input name="nummer" required placeholder="DFIR-2026-0002" />
        </label>
        <label>
          Titel
          <input name="titel" required />
        </label>
        <label>
          Fallordner auf dem Server
          <input name="ordner" placeholder="/mnt/evidence/fall-0002" />
        </label>
        <label>
          Zeitzone (aus der Registry, falls bekannt)
          <input name="zeitzone" />
        </label>
        <label className="breit">
          Beschreibung
          <textarea name="beschreibung" rows={2} />
        </label>
      </div>
      <div className="aktionen">
        <button type="submit" disabled={anlegen.isPending}>
          Anlegen
        </button>
        <button type="button" className="leise" onClick={schliessen}>
          Abbrechen
        </button>
      </div>
      {anlegen.error && <p className="fehler">{anlegen.error.message}</p>}
    </form>
  );
}
