import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Button } from "../../components/ui/Button";
import { Badge } from "../../components/ui/Badge";
import { EmptyState, ErrorState, Timestamp } from "../../components/ui/Display";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/ui/Input";
import { useBookmarks, useFinding, useFindings, useSaveFinding } from "../../lib/api/queries";
import type { CaseBookmark, Finding } from "../../lib/api/types";
import { label } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

const categories=["execution","persistence","credential_access","exfiltration","lateral_movement","defense_evasion","user_activity","removable_media","network","other"];
const statuses=["new","in_review","confirmed","rejected","resolved"];
const dispositions=["unknown","benign","expected","suspicious","malicious","relevant","not_relevant"];
const h=columnHelper<Finding>();
const columns=[
  h.accessor("title",{header:"Finding",size:280}),
  h.accessor("status",{header:"Status",size:130,cell:c=><Badge>{label(c.getValue())}</Badge>}),
  h.accessor("priority",{header:"Priority",size:110,cell:c=>label(c.getValue())}),
  h.accessor("analyst",{header:"Analyst",size:140,cell:c=>c.getValue()??c.row.original.created_by}),
  h.accessor("updated_at",{header:"Updated (investigation time)",size:220,cell:c=><Timestamp value={c.getValue()}/>}),
];
type Ref={kind:"artifact"|"event"|"entity";target:string;title:string};
function bookmarkRef(b:CaseBookmark):Ref[] {
  return b.kind==="artifact"||b.kind==="event"||b.kind==="entity" ? [{kind:b.kind,target:b.target,title:b.title}] : [];
}
function Editor({number,finding,initialRef,onSaved,onCancel}:{number:string;finding?:Finding;initialRef?:Ref;onSaved:(f:Finding)=>void;onCancel:()=>void}) {
  const {can}=useSession(); const {open}=useDetail();
  const save=useSaveFinding(number,finding?.id); const bookmarks=useBookmarks(number);
  const [expectedVersion]=useState(finding?.updated_at);
  const [title,setTitle]=useState(finding?.title??""); const [description,setDescription]=useState(finding?.description??"");
  const [category,setCategory]=useState(finding?.category??"other"); const [priority,setPriority]=useState(finding?.priority??"medium");
  const [disposition,setDisposition]=useState(finding?.disposition??"unknown"); const [status,setStatus]=useState(finding?.status??"new");
  const [selected,setSelected]=useState<Ref[]>(initialRef?[initialRef]:[]);
  const existing:Ref[]=finding ? (["artifact","event","entity"] as const).flatMap(kind=>finding[`${kind}_refs`].map(target=>({kind,target,title:`${label(kind)} ${target}`}))) : [];
  const options=[...(initialRef?[initialRef]:[]),...(bookmarks.data?.pages.flatMap(p=>p.eintraege.flatMap(bookmarkRef))??[])].filter((r,i,all)=>all.findIndex(o=>o.kind===r.kind&&o.target===r.target)===i);
  const editable=can(finding?"finding.edit":"finding.create"); const refs=finding?existing:selected;
  const submit=()=>save.mutate(finding ? {title,description:description||null,category,priority,disposition,status,expected_updated_at:expectedVersion!} : {title,description:description||null,category,priority,disposition,entity_refs:selected.filter(r=>r.kind==="entity").map(r=>r.target),event_refs:selected.filter(r=>r.kind==="event").map(r=>r.target),artifact_refs:selected.filter(r=>r.kind==="artifact").map(r=>r.target)},{onSuccess:onSaved});
  return <section className="bookmark-entry">
    <h3>{finding?"Review finding":"Create finding"}</h3>
    <p className="muted">Analyst assessment. The status records your review; it does not change the source evidence.</p>
    <form onSubmit={e=>{e.preventDefault();submit();}}>
      <Field label="Title"><Input aria-label="Finding title" required maxLength={500} value={title} onChange={e=>setTitle(e.target.value)} disabled={!editable}/></Field>
      <Field label="Assessment and reasoning"><Textarea aria-label="Finding assessment" maxLength={16000} value={description} onChange={e=>setDescription(e.target.value)} disabled={!editable}/></Field>
      <div className="filter-bar">
        <Field label="Category"><Select aria-label="Finding category" value={category} onChange={e=>setCategory(e.target.value)} disabled={!editable}>{categories.map(v=><option key={v} value={v}>{label(v)}</option>)}</Select></Field>
        <Field label="Priority"><Select aria-label="Finding priority" value={priority} onChange={e=>setPriority(e.target.value)} disabled={!editable}>{["low","medium","high","critical"].map(v=><option key={v}>{v}</option>)}</Select></Field>
        <Field label="Disposition"><Select aria-label="Finding disposition" value={disposition} onChange={e=>setDisposition(e.target.value)} disabled={!editable}>{dispositions.map(v=><option key={v} value={v}>{label(v)}</option>)}</Select></Field>
        {finding&&<Field label="Review status"><Select aria-label="Finding status" value={status} onChange={e=>setStatus(e.target.value)} disabled={!editable}>{statuses.map(v=><option key={v} value={v}>{label(v)}</option>)}</Select></Field>}
      </div>
      <h4>Supporting sources</h4>
      {finding ? refs.map(r=><div className="row" key={`${r.kind}:${r.target}`}><Button type="button" size="sm" onClick={()=>open(r.kind,r.target)}>Open {label(r.kind)} source</Button><span className="muted mono">{r.target}</span></div>) : <>
        <p className="muted">Choose 1 to 100 artifacts, events or entities from Investigation selection. To cite a file, open one of its source artifacts or events first.</p>
        {options.map(r=><div className="row" key={`${r.kind}:${r.target}`}><Checkbox label={`${r.title} (${r.kind})`} checked={selected.some(s=>s.kind===r.kind&&s.target===r.target)} disabled={!editable} onChange={e=>setSelected(prev=>e.target.checked?[...prev,r]:prev.filter(s=>s.kind!==r.kind||s.target!==r.target))}/><Button type="button" size="sm" onClick={()=>open(r.kind,r.target)}>Open source</Button></div>)}
        {!options.length&&<EmptyState title="No supporting objects selected" text="Add source artifacts, events or entities to Investigation selection first."/>}
        {bookmarks.error&&<ErrorState title="Supporting sources unavailable" reason={bookmarks.error.message}/>}
        {bookmarks.hasNextPage&&<Button type="button" disabled={bookmarks.isFetching} onClick={()=>bookmarks.fetchNextPage({cancelRefetch:false})}>Load more supporting sources</Button>}
      </>}
      {finding&&finding.updated_at!==expectedVersion&&<p role="status">This finding changed since you opened it. Your draft is preserved. Load the latest assessment before saving.</p>}
      {save.error&&<ErrorState title="Finding could not be saved" reason={save.error.message}/>}
      <div className="row">{editable&&<Button type="submit" variant="primary" disabled={save.isPending||!title.trim()||(!finding&&(refs.length<1||refs.length>100))}>{finding?"Save assessment and status":"Create finding"}</Button>}<Button type="button" onClick={onCancel}>Close</Button></div>
    </form>
    {finding&&<p className="muted">{label(finding.derivation)} · Created by {finding.analyst??finding.created_by} at <Timestamp value={finding.created_at}/> · Updated <Timestamp value={finding.updated_at}/> · <Link to={`/cases/${encodeURIComponent(number)}/audit`}>Audit history</Link></p>}
  </section>;
}
export function FindingsPage({number}:{number:string}) {
  const list=useFindings(number); const [params,setParams]=useSearchParams(); const {can}=useSession();
  const id=params.get("finding"); const finding=useFinding(number,id);
  const [filter,setFilter]=useState(""); const [search,setSearch]=useState(""); const [editorVersion,setEditorVersion]=useState(0);
  const creating=params.get("create")==="1";
  const sourceKind=params.get("source_kind");const sourceId=params.get("source_id");
  const initialRef:Ref|undefined=sourceId&&(sourceKind==="artifact"||sourceKind==="event"||sourceKind==="entity") ? {kind:sourceKind,target:sourceId,title:`${label(sourceKind)} ${sourceId}`} : undefined;
  const choose=(id:string|null,create=false)=>setParams(p=>{const n=new URLSearchParams(p);for(const k of ["finding","create","source_kind","source_id"])n.delete(k);if(id)n.set("finding",id);if(create)n.set("create","1");return n;});
  const loaded=list.data?.pages.flatMap(p=>p.eintraege)??[];const rows=loaded.filter(f=>(!filter||f.status===filter)&&`${f.title} ${f.description??""}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="page bookmarks-page">
    <div className="row"><h2>Findings</h2><span className="spacer"/>{can("finding.create")&&<Button variant="primary" onClick={()=>choose(null,true)}>Create finding</Button>}</div>
    <p className="muted">Review analyst assessments alongside their supporting sources. Every change is recorded in Audit and War Room.</p>
    <div className="filter-bar"><Input aria-label="Filter findings" placeholder="Filter loaded titles and assessments" value={search} onChange={e=>setSearch(e.target.value)}/><Select aria-label="Filter findings by status" value={filter} onChange={e=>setFilter(e.target.value)}><option value="">All statuses</option>{statuses.map(v=><option key={v} value={v}>{label(v)}</option>)}</Select><Button onClick={()=>list.refetch()} disabled={list.isFetching}>Refresh</Button></div>
    <p className="muted">{loaded.length} loaded findings. Filters apply to loaded pages.</p>
    {list.error&&<ErrorState title="Findings unavailable" reason={list.error.message}/>}
    {list.isPending&&<p role="status">Loading findings…</p>}
    {rows.length>0&&<DataTable label="Findings review list" height={Math.min(rows.length*36+40,300)} data={rows} columns={columns} rowId={f=>f.id} selected={id} grow={["title"]} onSelect={f=>choose(f.id)}/>}
    {!list.isPending&&!list.error&&!rows.length&&<EmptyState title="No matching findings" text="Create an assessment from the objects in Investigation selection."/>}
    {list.hasNextPage&&<Button disabled={list.isFetching} onClick={()=>list.fetchNextPage({cancelRefetch:false})}>Load more findings</Button>}
    {creating&&<Editor key={`new:${initialRef?.kind}:${initialRef?.target}`} number={number} initialRef={initialRef} onSaved={f=>choose(f.id)} onCancel={()=>choose(null)}/>}
    {id&&finding.error&&<ErrorState title="Finding unavailable" reason={finding.error.message}/>}
    {id&&finding.data&&<><Editor key={`${id}:${editorVersion}`} number={number} finding={finding.data} onSaved={()=>setEditorVersion(v=>v+1)} onCancel={()=>choose(null)}/><Button onClick={()=>{void finding.refetch().then(()=>setEditorVersion(v=>v+1));}}>Load latest assessment</Button></>}
  </div>;
}
