// Administration (nur Superadmin): Registrierungen freigeben oder ablehnen,
// Konten sperren und wieder freigeben, Rollen setzen, Passwort zurücksetzen,
// Superadmin übergeben. Jede Aktion steht im Audit.

import { useState } from "react";
import { Check, KeyRound, Lock, ShieldCheck, Unlock, UserCog, X } from "lucide-react";
import { Badge, StatusBadge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Checkbox, Field, Input } from "../../components/ui/Input";
import { Panel } from "../../components/ui/Layout";
import { useAccountAction, useAccounts, useRoles } from "../../lib/api/queries";
import type { Role, User } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";

const STATUS = {
  pending: { tone: "warning", text: "Pending" },
  active: { tone: "success", text: "Active" },
  disabled: { tone: "neutral", text: "Disabled" },
  rejected: { tone: "danger", text: "Rejected" },
} as const;

function RolePicker({ roles, value, onChange }: { roles: Role[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="role-picker">
      {roles.map((r) => (
        <Checkbox
          key={r.id}
          label={r.name}
          hint={r.description ?? undefined}
          checked={value.includes(r.id)}
          onChange={(e) => onChange(e.target.checked ? [...value, r.id] : value.filter((x) => x !== r.id))}
        />
      ))}
    </div>
  );
}

function Pending({ u, roles }: { u: User; roles: Role[] }) {
  const analyst = roles.find((r) => r.name === "Analyst")?.id;
  const [pick, setPick] = useState<string[]>(analyst ? [analyst] : []);
  const act = useAccountAction();
  return (
    <div className="admin-pending">
      <div className="row">
        <strong>{u.display_name}</strong>
        <span className="mono muted">{u.username}</span>
        <span className="spacer" />
        <span className="muted">
          registered <Timestamp value={u.created_at} />
        </span>
      </div>
      <RolePicker roles={roles} value={pick} onChange={setPick} />
      {act.error && <div className="form-error">{act.error.message}</div>}
      <div className="form-actions">
        <Button
          variant="primary"
          icon={<Check />}
          disabled={act.isPending || pick.length === 0}
          onClick={() => act.mutate({ id: u.id, action: "freigeben", body: { rollen: pick } })}
        >
          Approve with {pick.length} {pick.length === 1 ? "role" : "roles"}
        </Button>
        <Button variant="danger" icon={<X />} disabled={act.isPending} onClick={() => act.mutate({ id: u.id, action: "ablehnen" })}>
          Reject
        </Button>
      </div>
    </div>
  );
}

function Account({ u, roles, self }: { u: User; roles: Role[]; self: boolean }) {
  const [mode, setMode] = useState<null | "roles" | "password" | "superadmin">(null);
  const [pick, setPick] = useState<string[]>(u.roles);
  const [pw, setPw] = useState("");
  const act = useAccountAction();
  const names = u.roles.map((id) => roles.find((r) => r.id === id)?.name ?? id.slice(0, 8));
  const s = STATUS[u.status];
  const done = () => {
    setMode(null);
    setPw("");
  };
  return (
    <div className="admin-account">
      <div className="admin-row">
        <div className="admin-who">
          <strong>{u.display_name}</strong>
          <span className="mono muted">{u.username}</span>
        </div>
        <StatusBadge tone={s.tone} label={s.text} />
        {u.superadmin && <Badge tone="info" icon={<ShieldCheck />}>Superadmin</Badge>}
        {u.kind === "service" && <Badge outline>Service</Badge>}
        {u.password_change_required && <Badge tone="warning">Must change password</Badge>}
        <span className="admin-roles muted">{u.superadmin ? "all permissions" : names.join(", ") || "no roles"}</span>
        <span className="spacer" />
        {!u.superadmin && u.status === "active" && (
          <>
            <Button size="sm" icon={<UserCog />} onClick={() => setMode(mode === "roles" ? null : "roles")}>
              Roles
            </Button>
            {u.kind === "human" && (
              <Button size="sm" icon={<KeyRound />} onClick={() => setMode(mode === "password" ? null : "password")}>
                Reset password
              </Button>
            )}
            {u.kind === "human" && (
              <Button size="sm" icon={<ShieldCheck />} onClick={() => setMode(mode === "superadmin" ? null : "superadmin")}>
                Make superadmin
              </Button>
            )}
            <Button size="sm" variant="danger" icon={<Lock />} disabled={act.isPending} onClick={() => act.mutate({ id: u.id, action: "sperren" })}>
              Disable
            </Button>
          </>
        )}
        {u.status === "disabled" && (
          <Button size="sm" icon={<Unlock />} disabled={act.isPending} onClick={() => act.mutate({ id: u.id, action: "freigeben", body: { rollen: u.roles } })}>
            Enable
          </Button>
        )}
        {self && <span className="muted">you</span>}
      </div>
      {mode === "roles" && (
        <div className="inline-panel">
          <RolePicker roles={roles} value={pick} onChange={setPick} />
          <div className="form-actions">
            <Button variant="primary" disabled={act.isPending} onClick={() => act.mutate({ id: u.id, action: "rollen", body: { rollen: pick } }, { onSuccess: done })}>
              Save roles
            </Button>
            <Button variant="ghost" onClick={() => setMode(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {mode === "password" && (
        <form
          className="inline-panel"
          onSubmit={(e) => {
            e.preventDefault();
            act.mutate({ id: u.id, action: "passwort", body: { neu: pw } }, { onSuccess: done });
          }}
        >
          <Field label={`Temporary password for ${u.username}`} hint="At least 12 characters. The user must replace it at the next sign-in; open sessions end.">
            <Input type="password" autoComplete="new-password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} />
          </Field>
          <div className="form-actions">
            <Button type="submit" variant="primary" disabled={act.isPending}>
              Set password
            </Button>
            <Button variant="ghost" onClick={() => setMode(null)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
      {mode === "superadmin" && (
        <div className="inline-panel">
          <span>
            There is exactly one superadmin. Handing it to <strong>{u.username}</strong> removes it from your account
            immediately.
          </span>
          <div className="form-actions">
            <Button variant="danger" disabled={act.isPending} onClick={() => act.mutate({ id: u.id, action: "superadmin" }, { onSuccess: done })}>
              Hand over superadmin
            </Button>
            <Button variant="ghost" onClick={() => setMode(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {act.error && <div className="form-error">{act.error.message}</div>}
    </div>
  );
}

export function AdminPage() {
  const { me } = useSession();
  const accounts = useAccounts();
  const roles = useRoles();
  if (!me.konto.superadmin) {
    return (
      <div className="page">
        <EmptyState title="Administration is only available to the superadmin." />
      </div>
    );
  }
  const list = accounts.data ?? [];
  const pending = list.filter((u) => u.status === "pending");
  const others = list.filter((u) => u.status !== "pending" && !(u.kind === "service" && u.status === "disabled"));
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <span className="muted">Accounts and their roles. Every change is recorded in the audit log.</span>
        </div>
      </div>
      {(accounts.isPending || roles.isPending) && <Skeleton lines={6} />}
      {accounts.error && <ErrorState title="Accounts could not be loaded." reason={accounts.error.message} />}
      {accounts.data && roles.data && (
        <>
          <Panel title={`Pending registrations (${pending.length})`}>
            {pending.length === 0 ? (
              <span className="muted">No registrations waiting for approval.</span>
            ) : (
              <div className="stack">
                {pending.map((u) => (
                  <Pending key={u.id} u={u} roles={roles.data} />
                ))}
              </div>
            )}
          </Panel>
          <Panel title={`Accounts (${others.length})`}>
            <div className="admin-list">
              {others.map((u) => (
                <Account key={u.id} u={u} roles={roles.data} self={u.id === me.konto.id} />
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
