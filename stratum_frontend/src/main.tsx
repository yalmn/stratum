import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./design-system/tokens.css";
import "./design-system/base.css";
import "./design-system/components.css";
import "./design-system/shell.css";
import { ApiError, isUnauthorized } from "./lib/api/client";
import { keys } from "./lib/api/queries";
import { AppShell } from "./app/layouts/AppShell";
import { SessionGate } from "./features/auth/SessionGate";
import { CaseLayout } from "./features/cases/CaseLayout";
import { CasesPage } from "./features/cases/CasesPage";
import { DesignSystemPage } from "./design-system/DesignSystemPage";

const client: QueryClient = new QueryClient({
  // Läuft die Sitzung ab, zurück zur Anmeldung. /ich selbst nicht, sonst
  // fragte eine 401 dort endlos neu an.
  queryCache: new QueryCache({
    onError: (e, query) => {
      if (isUnauthorized(e) && query.queryKey[0] !== keys.me[0]) {
        void client.invalidateQueries({ queryKey: keys.me });
      }
    },
  }),
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
      refetchOnWindowFocus: false,
      staleTime: 10_000,
    },
  },
});

const root = document.getElementById("wurzel");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={client}>
        <BrowserRouter>
          <SessionGate>
            <AppShell>
              <Routes>
                <Route path="/" element={<Navigate to="/cases" replace />} />
                <Route path="/cases" element={<CasesPage />} />
                <Route path="/cases/:number/*" element={<CaseLayout />} />
                <Route path="/dev/design-system" element={<DesignSystemPage />} />
                <Route path="*" element={<Navigate to="/cases" replace />} />
              </Routes>
            </AppShell>
          </SessionGate>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  );
}
