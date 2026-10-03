import { useParams } from "react-router-dom";
import { EmptyState } from "../../components/ui/Display";
import { CASE_ITEMS } from "../../app/navigation";

/** Deep Link auf eine Ansicht, die noch nicht gebaut ist. */
export function PlannedView() {
  const view = useParams().view ?? "";
  const item = CASE_ITEMS.find((i) => i.id === view);
  return (
    <div className="page">
      <EmptyState
        title={item ? `${item.label} is not available yet.` : "Unknown view."}
        text={item?.planned ?? "Use the navigation on the left."}
      />
    </div>
  );
}
