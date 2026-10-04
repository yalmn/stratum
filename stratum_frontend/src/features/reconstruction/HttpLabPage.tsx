import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Play } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { Input, Select, Textarea } from "../../components/ui/Input";
import { ErrorState, Timestamp } from "../../components/ui/Display";
import { JobStatusBadge, DerivationBadge } from "../../components/forensic/Badges";
import { useHttpReplay, useJobs } from "../../lib/api/queries";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";
import type { HttpReplayRequest } from "../../lib/api/types";

export function HttpLabPage({number}:{number:string}) {
  const [params]=useSearchParams();
  const [direction,setDirection]=useState<"incoming"|"outgoing">(params.get("direction")==="outgoing"?"outgoing":"incoming");
  const [url,setUrl]=useState(params.get("target")??"");
  const [method,setMethod]=useState("GET");
  const [headers,setHeaders]=useState("");
  const [body,setBody]=useState("");
  const [status,setStatus]=useState("200");
  const [response,setResponse]=useState("Synthetic response");
  const [hypothesis,setHypothesis]=useState("");
  const [inputError,setInputError]=useState("");
  const {can}=useSession();
  const replay=useHttpReplay(number);
  const jobs=useJobs(number);
  const {open}=useDetail();
  const sourceKind=params.get("source_kind"),sourceId=params.get("source_id");
  const target=params.get("target"),initialDirection=params.get("direction");
  useEffect(()=>{
    setDirection(initialDirection==="outgoing"?"outgoing":"incoming");
    setUrl(target??""); setMethod("GET"); setHeaders(""); setBody("");
    setStatus("200"); setResponse("Synthetic response"); setHypothesis(""); setInputError("");
  },[number,target,initialDirection,sourceKind,sourceId]);
  const source:HttpReplayRequest["source"]=(sourceKind==="artifact"||sourceKind==="entity")&&sourceId?{kind:sourceKind,id:sourceId}:null;
  const allowed=can("connector.use")&&can("analysis.start")&&can("file.view");
  function submit(e:React.FormEvent) {
    e.preventDefault(); setInputError("");
    const parsed:[string,string][]=[];
    for(const line of headers.split(/\r?\n/).filter((s)=>s.trim())) {
      const i=line.indexOf(":");
      if(i<1) {setInputError("Use one Header: value per line.");return;}
      parsed.push([line.slice(0,i).trim(),line.slice(i+1).trim()]);
    }
    const request:HttpReplayRequest={direction,url,method,headers:parsed,body,simulated_status:Number(status),simulated_body:response,hypothesis,source};
    replay.mutate(request);
  }
  const recorded=jobs.data?.filter((j)=>j.kind==="http_replay")??[];
  return <div className="page http-lab-page">
    <div className="row"><h2>HTTP reconstruction</h2><span className="badge">Offline simulation</span><DerivationBadge kind="reconstructed"/></div>
    <p className="muted">Reconstruct an incoming request from an attacker or an outgoing connection from the investigated system. This experiment uses a simulated server; it does not establish what happened historically.</p>
    <p className="lab-policy">Internet, production networks and host access are blocked. The original URL becomes a Host header only. HTTPS URLs replay HTTP semantics without TLS. Responses are displayed as text.</p>
    {source?<p className="muted">Linked {source.kind}. <Button size="sm" onClick={()=>open(source.kind,source.id)}>Open source</Button></p>:<p className="muted">Manual hypothesis. Open this tool from a source artifact or URL entity to retain that source reference.</p>}
    <form onSubmit={submit}>
      <div className="http-lab-columns">
        <section className="lab-editor stack" aria-label="Request editor">
          <h3>Request to reconstruct</h3>
          <label>Direction<Select value={direction} onChange={(e)=>setDirection(e.target.value as typeof direction)}><option value="incoming">Incoming attacker request</option><option value="outgoing">Outgoing suspicious connection</option></Select></label>
          <label>Original URL<Input aria-label="Original request URL" value={url} onChange={(e)=>setUrl(e.target.value)} placeholder="http://web01.invalid/admin/export" maxLength={2048}/></label>
          <label>Method<Select value={method} onChange={(e)=>setMethod(e.target.value)}>{["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"].map((m)=><option key={m}>{m}</option>)}</Select></label>
          <label>Headers<Textarea aria-label="Replay request headers" value={headers} onChange={(e)=>setHeaders(e.target.value)} placeholder="Content-Type: application/json" maxLength={65536}/></label>
          <small className="muted">One header per line. Transport headers are generated. Use synthetic values; Cookie and Authorization are not accepted.</small>
          <label>Request body<Textarea className="lab-code" aria-label="Replay request body" value={body} onChange={(e)=>setBody(e.target.value)} maxLength={65536}/></label>
        </section>
        <section className="lab-editor stack" aria-label="Simulated server">
          <h3>Simulated server response</h3>
          <p className="muted">Define the response assumption for this experiment. Application, database and exploit effects are not reconstructed by this simulator.</p>
          <label>Response status<Input aria-label="Simulated response status" type="number" min={200} max={599} value={status} onChange={(e)=>setStatus(e.target.value)}/></label>
          <label>Response body<Textarea className="lab-code" aria-label="Simulated response body" value={response} onChange={(e)=>setResponse(e.target.value)} maxLength={65536}/></label>
          <label>Hypothesis to test<Textarea aria-label="Replay hypothesis" value={hypothesis} onChange={(e)=>setHypothesis(e.target.value)} placeholder="Which request and response assumption should this experiment test?" maxLength={2000}/></label>
          <small className="muted">Up to 64 KiB UTF-8 per body. Each experiment stores its inputs, source, runtime and actual request/response transcript.</small>
        </section>
      </div>
      <div className="row"><Button type="submit" icon={<Play/>} disabled={!allowed||replay.isPending||!url.trim()||!hypothesis.trim()}>Run offline experiment</Button>{!allowed&&<small className="muted">Requires analysis.start, connector.use and file.view.</small>}</div>
      {inputError&&<ErrorState title="Request needs correction" reason={inputError}/>}
      {replay.error&&<ErrorState title="Experiment could not be queued" reason={replay.error.message}/>}
      {replay.data&&<p role="status">Offline experiment queued. <Button size="sm" onClick={()=>open("job",replay.data!.job_id)}>Open experiment</Button></p>}
    </form>
    <h3>Recorded experiments</h3>
    {jobs.error&&<ErrorState title="Experiments unavailable" reason={jobs.error.message}/>}
    <div className="list">{recorded.map((j)=>{const p=j.parameters as unknown as HttpReplayRequest;return <button key={j.id} type="button" className="list-row" onClick={()=>open("job",j.id)}><span className="badge">{p.direction}</span><span className="list-main mono">{p.method} {p.url}</span><Timestamp value={j.created_at}/><JobStatusBadge status={j.status}/></button>;})}</div>
    {jobs.data&&!recorded.length&&<p className="muted">No HTTP experiments recorded yet.</p>}
  </div>;
}
