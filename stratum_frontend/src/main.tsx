import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiFehler } from "./api";
import { MitSitzung, useSitzung } from "./sitzung";
import { Faelle } from "./seiten/Faelle";
import { FallSeite } from "./seiten/Fall";
import "./stil.css";

const client: QueryClient = new QueryClient({
  // Läuft die Sitzung ab, zurück zur Anmeldung. `/ich` selbst nicht, sonst
  // fragte eine 401 dort endlos neu an.
  queryCache: new QueryCache({
    onError: (e, anfrage) => {
      if (e instanceof ApiFehler && e.status === 401 && anfrage.queryKey[0] !== "ich") {
        void client.invalidateQueries({ queryKey: ["ich"] });
      }
    },
  }),
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof ApiFehler && e.status < 500) && n < 2,
      refetchOnWindowFocus: false,
    },
  },
});

function Rahmen() {
  const { ich, abmelden } = useSitzung();
  return (
    <>
      <header className="kopf">
        <Link to="/" className="marke">
          stratum
        </Link>
        <nav>
          <Link to="/">Fälle</Link>
        </nav>
        <span className="konto">
          {ich.konto.display_name} ({ich.konto.username})
          <button type="button" className="leise" onClick={abmelden}>
            Abmelden
          </button>
        </span>
      </header>
      <main className="inhalt">
        <Routes>
          <Route path="/" element={<Faelle />} />
          <Route path="/faelle/:nummer/*" element={<FallSeite />} />
          <Route path="*" element={<p className="hinweis">Seite nicht gefunden.</p>} />
        </Routes>
      </main>
    </>
  );
}

const wurzel = document.getElementById("wurzel");
if (wurzel) {
  createRoot(wurzel).render(
    <StrictMode>
      <QueryClientProvider client={client}>
        <BrowserRouter>
          <MitSitzung>
            <Rahmen />
          </MitSitzung>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  );
}
