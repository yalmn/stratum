import { Link, useMatch, useNavigate } from "react-router-dom";
import { ChevronDown, KeyRound, LogOut, Palette, Search, ShieldAlert, ShieldCheck, User } from "lucide-react";
import { Kbd, MOD } from "../../components/ui/Kbd";
import { Menu, Popover } from "../../components/ui/Overlay";
import { Tooltip } from "../../components/ui/Tooltip";
import { integrity } from "../../components/forensic/Badges";
import { JobsCenter, Notifications } from "../../features/jobs/JobsCenter";
import { useCase, useLogout } from "../../lib/api/queries";
import { useSession } from "../../lib/permissions";
import { useWorkspace } from "../store";

function CaseContext({ number }: { number: string }) {
  const c = useCase(number);
  return (
    <div className="top-case">
      <span className="sep">/</span>
      <Link to={`/cases/${encodeURIComponent(number)}/overview`} className="mono top-case-number">
        {number}
      </Link>
      {c.data && <span className="top-case-title">{c.data.fall.title}</span>}
    </div>
  );
}

/** Stand der Integrität aller Evidence im geöffneten Fall. */
function Integrity({ number }: { number: string }) {
  const c = useCase(number);
  const ev = c.data?.evidence ?? [];
  if (ev.length === 0) {
    return null;
  }
  const verified = ev.filter((e) => integrity(e).verified).length;
  const all = verified === ev.length;
  return (
    <Tooltip
      side="below"
      text={`${verified} of ${ev.length} evidence sources were re-hashed and matched before a completed analysis. The others have their SHA-256 recorded at import.`}
    >
      <span className={all ? "top-integrity ok" : "top-integrity"} tabIndex={0}>
        {all ? <ShieldCheck /> : <ShieldAlert />}
        Evidence integrity: {all ? "Verified" : `${verified}/${ev.length} verified`}
      </span>
    </Tooltip>
  );
}

function UserMenu() {
  const { me } = useSession();
  const logout = useLogout();
  const navigate = useNavigate();
  return (
    <Popover
      align="right"
      trigger={({ toggle, open }) => (
        <button type="button" className={open ? "top-btn active" : "top-btn"} onClick={toggle}>
          <User />
          <span>{me.konto.display_name}</span>
          <ChevronDown size={14} />
        </button>
      )}
    >
      {(close) => (
        <>
          <div className="menu-label">
            <strong>{me.konto.display_name}</strong>
            <div className="muted mono">{me.konto.username}</div>
            <div className="muted">{me.konto.superadmin ? "Superadmin" : `${me.rechte.length} permissions`}</div>
          </div>
          <div className="menu-sep" />
          <Menu
            close={close}
            entries={[
              { label: "Change password", icon: <KeyRound />, onSelect: () => navigate("/account") },
              ...(me.konto.superadmin
                ? [{ label: "Administration", icon: <ShieldCheck />, onSelect: () => navigate("/admin") }]
                : []),
              { label: "Design system", icon: <Palette />, onSelect: () => navigate("/dev/design-system") },
              "separator",
              { label: "Sign out", icon: <LogOut />, onSelect: () => logout.mutate() },
            ]}
          />
        </>
      )}
    </Popover>
  );
}

export function Topbar() {
  const match = useMatch("/cases/:number/*");
  const number = match?.params.number;
  const setPalette = useWorkspace((s) => s.setPalette);
  return (
    <header className="topbar">
      <div className="top-left">
        <Link to="/cases" className="brand">
          STRATUM
        </Link>
        {number && <CaseContext number={number} />}
      </div>
      <button type="button" className="top-search" onClick={() => setPalette(true)}>
        <span className="row">
          <Search size={15} aria-hidden />
          Search Stratum…
        </span>
        <Kbd>{MOD}K</Kbd>
      </button>
      <div className="top-right">
        {number && <Integrity number={number} />}
        <JobsCenter />
        <Notifications />
        <UserMenu />
      </div>
    </header>
  );
}
