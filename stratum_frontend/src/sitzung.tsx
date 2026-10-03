import { createContext, useContext, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiFehler, type Ich } from "./api";

interface SitzungWert {
  ich: Ich;
  darf: (recht: string) => boolean;
  abmelden: () => void;
}

const Sitzung = createContext<SitzungWert | null>(null);

export function useSitzung(): SitzungWert {
  const s = useContext(Sitzung);
  if (!s) {
    throw new Error("useSitzung außerhalb der Sitzung");
  }
  return s;
}

// Zeigt die Anmeldung, bis `/ich` ein Konto liefert.
export function MitSitzung({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const ich = useQuery({
    queryKey: ["ich"],
    queryFn: () => api<Ich>("/ich"),
    retry: false,
    staleTime: 60_000,
  });
  const abmelden = useMutation({
    mutationFn: () => api<void>("/sitzung", { methode: "DELETE" }),
    onSettled: () => client.clear(),
  });

  if (ich.isPending) {
    return <p className="hinweis mitte">Lade …</p>;
  }
  if (ich.error) {
    if (ich.error instanceof ApiFehler && ich.error.status === 401) {
      return <Anmeldung />;
    }
    return <p className="fehler mitte">{ich.error.message}</p>;
  }
  const wert: SitzungWert = {
    ich: ich.data,
    darf: (r) => ich.data.konto.superadmin || ich.data.rechte.includes(r),
    abmelden: () => abmelden.mutate(),
  };
  return <Sitzung.Provider value={wert}>{children}</Sitzung.Provider>;
}

function Anmeldung() {
  const client = useQueryClient();
  const anmelden = useMutation({
    mutationFn: (d: { name: string; passwort: string }) =>
      api<unknown>("/sitzung", { methode: "POST", daten: d }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["ich"] }),
  });
  return (
    <main className="anmeldung">
      <h1>stratum</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          anmelden.mutate({
            name: String(f.get("name") ?? "").trim(),
            passwort: String(f.get("passwort") ?? ""),
          });
        }}
      >
        <label>
          Anmeldename
          <input name="name" autoComplete="username" autoFocus required />
        </label>
        <label>
          Passwort
          <input name="passwort" type="password" autoComplete="current-password" required />
        </label>
        <button type="submit" disabled={anmelden.isPending}>
          Anmelden
        </button>
        {anmelden.error && <p className="fehler">{anmelden.error.message}</p>}
      </form>
    </main>
  );
}
