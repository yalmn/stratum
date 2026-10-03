import { useState, type ReactNode } from "react";
import { Button } from "../../components/ui/Button";
import { ErrorState, Skeleton, Tabs } from "../../components/ui/Display";
import { Field, Input } from "../../components/ui/Input";
import { isUnauthorized } from "../../lib/api/client";
import { useChangeOwnPassword, useLogin, useLogout, useMe, useRegister } from "../../lib/api/queries";
import { SessionContext, sessionFor } from "../../lib/permissions";

const MIN = 12;

/** Anmeldung bzw. Registrierung, bis /ich ein Konto liefert; muss das
 * Konto sein Passwort ändern, zuerst das. */
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
  if (me.data.konto.password_change_required) {
    return <ForcedPasswordChange name={me.data.konto.username} />;
  }
  return <SessionContext.Provider value={sessionFor(me.data)}>{children}</SessionContext.Provider>;
}

function Login() {
  const [tab, setTab] = useState<"login" | "register">("login");
  return (
    <main className="login">
      <div className="login-brand">STRATUM</div>
      <p className="muted">Digital forensics and incident response workspace</p>
      <Tabs
        active={tab}
        onSelect={(t) => setTab(t as "login" | "register")}
        items={[
          { id: "login", label: "Sign in" },
          { id: "register", label: "Create account" },
        ]}
      />
      {tab === "login" ? <SignIn /> : <Register onDone={() => setTab("login")} />}
      <p className="muted login-foot">Every action in stratum is recorded in the audit log.</p>
    </main>
  );
}

function SignIn() {
  const login = useLogin();
  return (
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
      {login.error && (
        <div className="form-error">
          {login.error.message === "Anmeldung abgelehnt"
            ? "Sign-in refused. Check name and password; new accounts need approval by the superadmin."
            : login.error.message}
        </div>
      )}
      <Button type="submit" variant="primary" disabled={login.isPending}>
        Sign in
      </Button>
    </form>
  );
}

function Register({ onDone }: { onDone: () => void }) {
  const register = useRegister();
  const [mismatch, setMismatch] = useState(false);
  if (register.data) {
    return (
      <div className="stack">
        <div className="empty">
          <strong>Account {register.data.username} created.</strong>
          <span>The superadmin has to approve it and assign roles before you can sign in.</span>
        </div>
        <Button onClick={onDone}>Back to sign in</Button>
      </div>
    );
  }
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const p = String(f.get("passwort") ?? "");
        if (p !== String(f.get("wiederholt") ?? "")) {
          setMismatch(true);
          return;
        }
        setMismatch(false);
        register.mutate({
          name: String(f.get("name") ?? "").trim().toLowerCase(),
          anzeigename: String(f.get("anzeigename") ?? "").trim(),
          passwort: p,
        });
      }}
    >
      <Field label="Username" hint="Lowercase letters, digits, . _ -">
        <Input name="name" autoComplete="username" pattern="[a-z0-9._\-]{1,64}" required autoFocus />
      </Field>
      <Field label="Display name">
        <Input name="anzeigename" autoComplete="name" required maxLength={120} />
      </Field>
      <Field label="Password" hint={`At least ${MIN} characters`}>
        <Input name="passwort" type="password" autoComplete="new-password" minLength={MIN} required />
      </Field>
      <Field label="Repeat password">
        <Input name="wiederholt" type="password" autoComplete="new-password" minLength={MIN} required />
      </Field>
      {mismatch && <div className="form-error">The passwords do not match.</div>}
      {register.error && <div className="form-error">{register.error.message}</div>}
      <Button type="submit" variant="primary" disabled={register.isPending}>
        Create account
      </Button>
    </form>
  );
}

/** Formular für den Passwortwechsel; auch aus dem Kontomenü erreichbar. */
export function ChangePasswordForm({ onDone }: { onDone?: () => void }) {
  const change = useChangeOwnPassword();
  const [mismatch, setMismatch] = useState(false);
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const neu = String(f.get("neu") ?? "");
        if (neu !== String(f.get("wiederholt") ?? "")) {
          setMismatch(true);
          return;
        }
        setMismatch(false);
        change.mutate({ bisher: String(f.get("bisher") ?? ""), neu }, { onSuccess: () => onDone?.() });
      }}
    >
      <Field label="Current password">
        <Input name="bisher" type="password" autoComplete="current-password" required autoFocus />
      </Field>
      <Field label="New password" hint={`At least ${MIN} characters`}>
        <Input name="neu" type="password" autoComplete="new-password" minLength={MIN} required />
      </Field>
      <Field label="Repeat new password">
        <Input name="wiederholt" type="password" autoComplete="new-password" minLength={MIN} required />
      </Field>
      {mismatch && <div className="form-error">The new passwords do not match.</div>}
      {change.error && (
        <div className="form-error">
          {change.error.message === "bisheriges Passwort falsch" ? "The current password is wrong." : change.error.message}
        </div>
      )}
      <Button type="submit" variant="primary" disabled={change.isPending}>
        Change password
      </Button>
      <span className="muted">All sessions of this account end; sign in again with the new password.</span>
    </form>
  );
}

function ForcedPasswordChange({ name }: { name: string }) {
  const logout = useLogout();
  return (
    <main className="login">
      <div className="login-brand">STRATUM</div>
      <div className="stack">
        <strong>Set your own password</strong>
        <span className="muted">
          The account <span className="mono">{name}</span> uses an initial or reset password. Replace it before you
          continue.
        </span>
      </div>
      <ChangePasswordForm />
      <Button variant="ghost" onClick={() => logout.mutate()}>
        Sign out
      </Button>
    </main>
  );
}
