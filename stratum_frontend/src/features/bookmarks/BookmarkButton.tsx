import { Bookmark, BookmarkCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { ErrorState } from "../../components/ui/Display";
import { useBookmarkStatus, useSaveBookmark } from "../../lib/api/queries";
import type { BookmarkKind } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";

export function BookmarkButton({number,kind,target}:{number:string;kind:BookmarkKind;target:string}) {
  const {can}=useSession();
  const status=useBookmarkStatus(number,kind,target);
  const save=useSaveBookmark(number);
  const navigate=useNavigate();
  const saved=!!status.data?.bookmark;
  return <div>
    <Button size="sm" icon={saved?<BookmarkCheck/>:<Bookmark/>} disabled={status.isPending||save.isPending||!!status.error||(!saved&&!can("bookmark.edit"))} onClick={()=>saved?navigate(`/cases/${encodeURIComponent(number)}/bookmarks`):save.mutate({kind,target})}>
      {saved?"Saved in investigation":"Add to investigation"}
    </Button>
    {!saved&&!can("bookmark.edit")&&<small className="muted">Requires bookmark.edit</small>}
    {(status.error||save.error)&&<ErrorState title="Investigation selection unavailable" reason={(status.error??save.error)?.message}/>}
  </div>;
}
