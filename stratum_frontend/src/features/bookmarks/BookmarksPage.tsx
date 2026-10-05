import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { Checkbox, Input, Select, Textarea } from "../../components/ui/Input";
import { EmptyState, ErrorState, Timestamp } from "../../components/ui/Display";
import { useBookmarks, useSaveBookmark } from "../../lib/api/queries";
import type { CaseBookmark } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";

function destination(number:string,b:CaseBookmark) {
  const view={file:"explorer",event:"timeline",entity:"entities",relationship:"graph",artifact:"bookmarks"}[b.kind];
  return `/cases/${encodeURIComponent(number)}/${view}?detail=${b.kind}:${encodeURIComponent(b.target)}`;
}
function Entry({number,b}:{number:string;b:CaseBookmark}) {
  const [note,setNote]=useState(b.note);
  const [reviewed,setReviewed]=useState(b.reviewed);
  const [version,setVersion]=useState(b.updated_at);
  const save=useSaveBookmark(number);
  const {can}=useSession();
  const navigate=useNavigate();
  const dirty=note!==b.note||reviewed!==b.reviewed;
  return <article className="bookmark-entry">
    <div className="row"><Link className="list-main" to={destination(number,b)}>{b.title}</Link><span className="badge">{b.kind}</span><span className="badge">{b.reviewed?"Reviewed":"To review"}</span></div>
    <p className="muted mono">{b.target}</p>
    <label>Investigation note<Textarea aria-label={`Note for ${b.title}`} value={note} onChange={(e)=>setNote(e.target.value)} maxLength={8000} disabled={!can("bookmark.edit")}/></label>
    <div className="row"><Checkbox label="Reviewed by analyst" checked={reviewed} onChange={(e)=>setReviewed(e.target.checked)} disabled={!can("bookmark.edit")}/><span className="spacer"/>
    {can("finding.create")&&(b.kind==="artifact"||b.kind==="event"||b.kind==="entity")&&<Button size="sm" onClick={()=>navigate(`/cases/${encodeURIComponent(number)}/findings?create=1&source_kind=${b.kind}&source_id=${encodeURIComponent(b.target)}`)}>Create finding</Button>}
    {can("bookmark.edit")&&<><Button size="sm" disabled={!dirty||save.isPending} onClick={()=>save.mutate({kind:b.kind,target:b.target,note,reviewed,expected_updated_at:version},{onSuccess:(saved)=>{setNote(saved.note);setReviewed(saved.reviewed);setVersion(saved.updated_at);}})}>Save note and status</Button><Button size="sm" disabled={save.isPending||dirty} onClick={()=>save.mutate({kind:b.kind,target:b.target,removed:true,expected_updated_at:version})}>Remove from list</Button></>}
    </div>
    <p className="muted">Updated <Timestamp value={b.updated_at}/> · <span className="mono">{b.updated_by}</span></p>
    {version!==b.updated_at&&<p role="status" className="muted">This selection changed since you opened it. Your draft is preserved. <Button size="sm" onClick={()=>{setNote(b.note);setReviewed(b.reviewed);setVersion(b.updated_at);}}>Load latest note</Button></p>}
    {save.error&&<ErrorState title="Selection could not be saved" reason={save.error.message}/>}
  </article>;
}
export function BookmarksPage({number}:{number:string}) {
  const list=useBookmarks(number);
  const [text,setText]=useState(""); const [status,setStatus]=useState("");
  const loaded=list.data?.pages.flatMap((p)=>p.eintraege)??[];
  const rows=loaded.filter((b)=>(status===""||(status==="reviewed")===b.reviewed)&&`${b.title} ${b.note} ${b.target}`.toLocaleLowerCase().includes(text.toLocaleLowerCase()));
  return <div className="page bookmarks-page">
    <h2>Investigation selection</h2>
    <p className="muted">Shared case shortlist for objects that need closer examination. Notes and review status are analyst annotations, not confirmed findings. Sources and provenance remain unchanged.</p>
    <div className="filter-bar"><Input aria-label="Filter investigation selection" placeholder="Filter loaded objects and notes" value={text} onChange={(e)=>setText(e.target.value)}/><Select aria-label="Review status" value={status} onChange={(e)=>setStatus(e.target.value)}><option value="">All statuses</option><option value="pending">To review</option><option value="reviewed">Reviewed</option></Select><Button disabled={list.isFetching} onClick={()=>list.refetch()}>Refresh</Button></div>
    <p className="muted">{loaded.length} loaded objects. Filters apply to loaded pages.</p>
    {list.isPending&&<p role="status">Loading investigation selection…</p>}
    {list.error&&<ErrorState title="Selection could not be loaded" reason={list.error.message}/>}
    {!list.isPending&&!list.error&&!rows.length&&<EmptyState title="No objects in this selection" text="Open a file, event, entity or source artifact and choose Add to investigation."/>}
    {rows.map((b)=><Entry key={b.id} number={number} b={b}/>)}
    {list.hasNextPage&&<Button disabled={list.isFetchingNextPage} onClick={()=>list.fetchNextPage()}>Load older objects</Button>}
  </div>;
}
