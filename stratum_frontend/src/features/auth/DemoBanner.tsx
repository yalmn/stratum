import { useServerStatus } from "../../lib/api/queries";

/** Deutlicher Hinweis, solange der Server im Demo-Betrieb läuft. */
export function DemoBanner() {
  const status = useServerStatus();
  if (!status.data?.demo) {
    return null;
  }
  return (
    <div className="demo-banner" role="status">
      DEMO MODE · for demonstration only, not for casework
    </div>
  );
}
