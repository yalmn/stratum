import { CodeBlock, PropertyList, Timestamp } from "../../components/ui/Display";
import { DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";
interface Result {
  direction:string; hypothesis:string; started_at:string; finished_at:string;
  lab:{image_id:string;docker_version:string;exchange:{status:number;request_wire:string;response_wire:string;elapsed_ms:number;peer_ip:string;transport:string}};
}
export function HttpLabResult({value}:{value:Record<string,unknown>}) {
  if(value.werkzeug!=="HTTP Lab") return null;
  const r=value as unknown as Result,exchange=r.lab.exchange;
  return <>
    <DrawerSection title="HTTP reconstruction"><DerivationBadge kind="reconstructed"/><p className="muted">Offline exchange against a simulated server. This result is not historical evidence and does not confirm exploitation or persistence.</p><PropertyList items={[["Direction",r.direction],["Hypothesis",r.hypothesis],["Started",<Timestamp value={r.started_at}/>],["Finished",<Timestamp value={r.finished_at}/>],["Response status",String(exchange.status)],["Duration",`${exchange.elapsed_ms} ms`],["Actual peer",exchange.peer_ip],["Transport",exchange.transport],["TLS", "Not replayed"],["Image",<span className="mono">{r.lab.image_id}</span>],["Runtime",r.lab.docker_version]]}/></DrawerSection>
    <DrawerSection title="Sent request"><CodeBlock>{exchange.request_wire}</CodeBlock></DrawerSection>
    <DrawerSection title="Simulated response"><CodeBlock>{exchange.response_wire}</CodeBlock></DrawerSection>
  </>;
}
