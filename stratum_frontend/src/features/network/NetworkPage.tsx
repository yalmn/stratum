import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Globe } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { Checkbox, Input } from "../../components/ui/Input";
import { EmptyState, ErrorState, Timestamp } from "../../components/ui/Display";
import { JobStatusBadge } from "../../components/forensic/Badges";
import { useJobs, useNetworkLookup } from "../../lib/api/queries";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

export function NetworkPage({ number }: { number: string }) {
  const [params] = useSearchParams();
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [dns, setDns] = useState(true);
  const [whois, setWhois] = useState(false);
  const { can } = useSession();
  const lookup = useNetworkLookup(number);
  const jobs = useJobs(number);
  const { open } = useDetail();
  return <div className="page network-page">
    <h2>Network enrichment</h2>
    <p className="muted">Resolve an IP, domain or URL host using DNS and inspect its WHOIS registration. These are current external answers at investigation time, not proof of historical activity.</p>
    {can("connector.use") ? <form className="stack" onSubmit={(e) => { e.preventDefault(); lookup.mutate({ ziel:target, dns, whois }); }}>
      <Input aria-label="Network lookup target" placeholder="IP, domain or https:// URL" value={target} maxLength={2048} onChange={(e) => setTarget(e.target.value)} />
      <div className="row"><Checkbox label="DNS (A/AAAA or reverse PTR)" checked={dns} onChange={(e) => setDns(e.target.checked)} /><Checkbox label="WHOIS" checked={whois} onChange={(e) => setWhois(e.target.checked)} /></div>
      <p className="muted">Selected queries send the host to the VM's DNS resolver or WHOIS service. URL paths are not fetched. Linux worker with dnsutils / whois required.</p>
      <Button type="submit" icon={<Globe />} disabled={lookup.isPending || !target.trim() || (!dns && !whois)}>Queue selected lookups</Button>
      {lookup.error && <ErrorState title="Lookup job could not be created" reason={lookup.error.message} />}
      {lookup.data && <div role="status">Queued for <span className="mono">{lookup.data.host}</span>. <Button size="sm" onClick={() => open("job", lookup.data!.job_id)}>Open lookup job</Button></div>}
    </form> : <EmptyState title="Connector permission required" text="Your role needs connector.use to start external lookups." />}
    <h3>Recorded lookup jobs</h3>
    {jobs.error && <ErrorState title="Jobs could not be loaded" reason={jobs.error.message} />}
    <div className="list">{jobs.data?.filter((j) => j.kind === "network_enrichment").map((j) => <button type="button" key={j.id} className="list-row" onClick={() => open("job", j.id)}><span className="list-main mono">{String((j.parameters as Record<string, unknown>)?.host ?? "")}</span><Timestamp value={j.created_at} /><JobStatusBadge status={j.status} /></button>)}</div>
    {jobs.data && !jobs.data.some((j) => j.kind === "network_enrichment") && <p className="muted">No lookup jobs recorded yet.</p>}
  </div>;
}
