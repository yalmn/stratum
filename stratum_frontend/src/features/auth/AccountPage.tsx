import { useSession } from "../../lib/permissions";
import { ChangePasswordForm } from "./SessionGate";

export function AccountPage() {
  const { me } = useSession();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Account</h1>
          <span className="muted">
            {me.konto.display_name} · <span className="mono">{me.konto.username}</span>
          </span>
        </div>
      </div>
      <div className="account-form">
        <ChangePasswordForm />
      </div>
    </div>
  );
}
