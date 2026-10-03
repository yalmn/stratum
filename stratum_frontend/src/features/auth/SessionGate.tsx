import type { ReactNode } from "react";
import { Button } from "../../components/ui/Button";
import { ErrorState, Skeleton } from "../../components/ui/Display";
import { Field, Input } from "../../components/ui/Input";
import { isUnauthorized } from "../../lib/api/client";
import { useLogin, useMe } from "../../lib/api/queries";
import { SessionContext, sessionFor } from "../../lib/permissions";

/** Zeigt die Anmeldung, bis /ich ein Konto liefert. */
export function SessionGate({ children }: { children: ReactNode }) {
  const me = useMe();
  if (me.isPending) {
    return (
      <div className="login">
        <Skeleton lines={3} />
      </div>
    );
  }
  if (me.error) {
    return isUnauthorized(me.error) ? (
      <Login />
    ) : (
      <div className="login">
        <ErrorState title="The server is not reachable." reason={me.error.message} />
      </div>
    );
  }
  return <SessionContext.Provider value={sessionFor(me.data)}>{children}</SessionContext.Provider>;
}

function Login() {
  const login = useLogin();
  return (
    <main className="login">
      <div className="login-brand">STRATUM</div>
      <p className="muted">Digital forensics and incident response workspace</p>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          login.mutate({ name: String(f.get("name") ?? "").trim(), passwort: String(f.get("passwort") ?? "") });
        }}
      >
        <Field label="Username">
          <Input name="name" autoComplete="username" autoFocus required />
        </Field>
        <Field label="Password">
          <Input name="passwort" type="password" autoComplete="current-password" required />
        </Field>
        {login.error && <div className="form-error">{login.error.message}</div>}
        <Button type="submit" variant="primary" disabled={login.isPending}>
          Sign in
        </Button>
      </form>
      <p className="muted login-foot">Every action in stratum is recorded in the audit log.</p>
    </main>
  );
}
