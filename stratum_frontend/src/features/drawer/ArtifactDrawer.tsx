import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { CodeBlock, ErrorState, Skeleton } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { useRawFinding } from "../../lib/api/queries";
import { BookmarkButton } from "../bookmarks/BookmarkButton";
export function ArtifactDrawer({id,caseNumber,onClose}:{id:string;caseNumber:string;onClose:()=>void}) {
  const navigate=useNavigate();
  const query=useRawFinding(id,false,true);
  return <DrawerFrame kind="Artifact" title="Source artifact" onClose={onClose}>
    {query.isPending&&<Skeleton lines={8}/>}
    {query.error&&<ErrorState title="Source artifact unavailable" reason={query.error.message}/>}
    {query.data&&<><BookmarkButton number={caseNumber} kind="artifact" target={id}/><Button size="sm" onClick={()=>navigate(`/cases/${encodeURIComponent(caseNumber)}/reconstruction?source_kind=artifact&source_id=${id}`)}>Reconstruct HTTP request</Button><DrawerSection title="Raw finding"><p className="muted">Stored source output; credential secrets remain masked.</p><CodeBlock>{JSON.stringify(query.data.fund,null,2)}</CodeBlock></DrawerSection></>}
  </DrawerFrame>;
}
