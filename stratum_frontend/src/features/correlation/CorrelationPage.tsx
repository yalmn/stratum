import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Button } from "../../components/ui/Button";
import { Select } from "../../components/ui/Input";
import { CodeBlock, EmptyState, ErrorState, PropertyList, Timestamp } from "../../components/ui/Display";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useCorrelationRun, useCorrelationRuns, useCorrelations, useRunCorrelation } from "../../lib/api/queries";
import type { CorrelationMatch } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";
import { label } from "../../lib/format";

const h=columnHelper<CorrelationMatch>();
const columns=[
  h.accessor("entity_name",{header:"Shared entity",size:260}),
  h.accessor("rule_id",{header:"Rule",size:240,cell:c=>label(c.getValue())}),
  h.accessor("host_name",{header:"Host",size:180}),
  h.display({id:"time",header:"First source time (UTC)",size:230,cell:c=><Timestamp value={c.row.original.traces[0].time.utc}/>}),
  h.display({id:"derivation",header:"Derivation",size:130,cell:()=> <DerivationBadge kind="correlated"/>}),
];
export function CorrelationPage({number}:{number:string}) {
  const {can}=useSession();const {open}=useDetail();const navigate=useNavigate();
  const [params,setParams]=useSearchParams();const [filter,setFilter]=useState("");const [selected,setSelected]=useState<string|null>(null);
  const allowed=can("case.view")&&can("file.view");
  const runs=useCorrelationRuns(number,allowed);const execute=useRunCorrelation(number);
  const run=params.get("run")??runs.data?.runs[0]?.id??"";
  const results=useCorrelations(number,allowed?run:"");
  const metadata=useCorrelationRun(number,allowed?run:"");
  const current=metadata.data;
  const rows=results.data?.pages.flatMap(p=>p.eintraege)??[];
  const match=rows.find(r=>r.id===selected);const rule=current?.rules.find(r=>r.id===match?.rule_id);
  const base=`/cases/${encodeURIComponent(number)}`;
  function chooseRun(id:string) {setSelected(null);setParams(p=>{const n=new URLSearchParams(p);n.set("run",id);return n;});}
  if(!allowed)return <EmptyState title="Correlation permission required" text="Your role needs case.view and file.view to read sources."/>;
  return <div className="page bookmarks-page">
    <div className="row"><h2>Correlation</h2><span className="spacer"/>{can("analysis.start")&&<Button variant="primary" disabled={execute.isPending} onClick={()=>execute.mutate(undefined,{onSuccess:r=>chooseRun(r.id)})}>{execute.isPending?"Evaluating stored sources…":"Run correlation"}</Button>}</div>
    <p className="muted">Connect stored traces by normalized entity, host, evidence and source snapshot. Matches are computed context; they do not establish causality or malicious activity.</p>
    <details className="bookmark-entry"><summary>Rules and coverage</summary>
      <p>Only supported stored events with a host, source timestamp and byte anchor are considered. No image scan or external request is performed. Different evidence or snapshots are kept separate. Name-only Prefetch entities are not matched to path-based executable entities.</p>
      {(runs.data?.rules??[]).map(r=><p key={r.id}><strong>{r.title} · v{r.version}</strong><br/>{r.limitation}</p>)}
      <p className="muted">Limits per evaluation: 10,000 input source references, 200,000 comparisons and 500 matches. Missing or unsupported traces remain outside this coverage.</p>
    </details>
    {execute.error&&<ErrorState title="Correlation could not be run" reason={execute.error.message}/>}
    {runs.error&&<ErrorState title="Evaluations unavailable" reason={runs.error.message}/>}
    <div className="filter-bar">
      <Select aria-label="Correlation evaluation" value={run} onChange={e=>chooseRun(e.target.value)}><option value="">Select evaluation</option>{current&&!runs.data?.runs.some(r=>r.id===run)&&<option value={run}>{current.created_at} · {current.summary.matches} matches</option>}{runs.data?.runs.map(r=><option key={r.id} value={r.id}>{r.created_at} · {r.summary.matches} matches{r.summary.limited?" · Limited":""}</option>)}</Select>
      <Select aria-label="Correlation rule filter" value={filter} onChange={e=>setFilter(e.target.value)}><option value="">All loaded rules</option>{(current?.rules??runs.data?.rules??[]).map(r=><option key={r.id} value={r.id}>{r.title}</option>)}</Select>
      <Button disabled={runs.isFetching||results.isFetching} onClick={()=>{void runs.refetch();if(run){void results.refetch();void metadata.refetch();}}}>Refresh saved results</Button>
    </div>
    {current&&<p className="muted">{current.summary.input_count} input source references · {current.summary.excluded_count} excluded · {current.summary.comparisons} comparisons · {current.summary.matches} matches. Evaluated at <Timestamp value={current.created_at}/> (investigation time).</p>}
    {current?.summary.limited&&<p role="status" className="form-error">Evaluation stopped at a protection limit. Results are incomplete; an empty result would not establish absence.</p>}
    {metadata.error&&<ErrorState title="Evaluation metadata unavailable" reason={metadata.error.message}/>}
    {results.error&&<ErrorState title="Results unavailable" reason={results.error.message}/>}
    {!run&&<EmptyState title="No evaluation yet" text="Run correlation after analyzing evidence. Existing stored analysis results can be used directly."/>}
    {run&&results.data&&rows.length===0&&<EmptyState title="No contextual matches in this evaluation" text="Check the supported rules and source coverage above. This does not establish absence of execution, persistence or network activity."/>}
    {rows.length>0&&<DataTable label="Correlation results" data={rows.filter(r=>!filter||r.rule_id===filter)} columns={columns} rowId={r=>r.id} height={Math.min(Math.max(rows.length*36+80,150),330)} selected={selected} onSelect={r=>setSelected(r.id)} footer={`${rows.length} saved matches loaded`}/>}
    {results.hasNextPage&&<Button disabled={results.isFetching} onClick={()=>results.fetchNextPage({cancelRefetch:false})}>Load more matches</Button>}
    {match&&<section className="bookmark-entry">
      <div className="row"><h3>{rule?.title??label(match.rule_id)}</h3><DerivationBadge kind={match.derivation}/><span className="spacer"/><Button onClick={()=>setSelected(null)}>Close details</Button></div>
      <p>{rule?.limitation??"Saved rule information is not available yet. Read the evaluation metadata before assessing this match."}</p><PropertyList items={[["Rule version",match.rule_version],["Shared entity",match.entity_name],["Host",match.host_name],["Stable result ID",<span className="mono">{match.id}</span>]]}/>
      <div className="row"><Link to={`${base}/graph?entity=${match.traces[0].entity_id}`}>Show entity in Graph</Link><Link to={`${base}/timeline?ent=${match.traces[0].entity_id}&entname=${encodeURIComponent(match.entity_name)}`}>Entity timeline</Link>{can("finding.create")&&<Button onClick={()=>navigate(`${base}/findings?create=1&event_ids=${match.traces.map(t=>t.event_id).join(",")}`)}>Create finding from both events</Button>}</div>
      {match.traces.map((t,i)=><div className="graph-source" key={`${t.event_id}:${t.source.artifact_id}`}>
        <h4>Source {i+1}: {label(t.kind)} · <Timestamp value={t.time.utc}/></h4>
        <div className="row"><DerivationBadge kind={t.derivation}/><Button size="sm" onClick={()=>open("event",t.event_id)}>Open event</Button><Button size="sm" onClick={()=>open("artifact",t.source.artifact_id)}>Open artifact</Button><Button size="sm" onClick={()=>open("evidence",t.source.evidence_id)}>Open evidence</Button></div>
        <PropertyList items={[["Time semantics",label(t.time.semantics)],["Time precision",label(t.time.precision)],["Source parser",`${t.source.parser.name} · ${t.source.parser.version}`],["Analysis run",t.source.analysis_run_id]]}/>
        <CodeBlock>{JSON.stringify(t.source.source_locator,null,2)}</CodeBlock>
      </div>)}
    </section>}
  </div>;
}
