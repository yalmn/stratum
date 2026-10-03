import { NavLink, useMatch } from "react-router-dom";
import { ChevronDown, ChevronRight, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { IconButton } from "../../components/ui/Button";
import { Kbd } from "../../components/ui/Kbd";
import { Tooltip } from "../../components/ui/Tooltip";
import { CASE_NAV, GLOBAL_NAV, type NavItem } from "../navigation";
import { useWorkspace } from "../store";

function Item({ item, base, collapsed }: { item: NavItem; base: string; collapsed: boolean }) {
  const content = (
    <>
      {item.icon}
      {!collapsed && <span className="nav-label">{item.label}</span>}
      {!collapsed && item.key && !item.planned && (
        <span className="nav-key">
          <Kbd>G</Kbd>
          <Kbd>{item.key.toUpperCase()}</Kbd>
        </span>
      )}
    </>
  );
  const tip = item.planned ? `${item.label}: ${item.planned}` : item.label;
  const link = item.planned ? (
    <span className="nav-item disabled" aria-disabled="true" tabIndex={0}>
      {content}
    </span>
  ) : (
    <NavLink
      to={item.path!.startsWith("/") ? item.path! : `${base}/${item.path}`}
      end={item.path === "/cases"}
      className="nav-item"
    >
      {content}
    </NavLink>
  );
  return collapsed || item.planned ? (
    <Tooltip text={tip} side="right">
      {link}
    </Tooltip>
  ) : (
    link
  );
}

export function Sidebar() {
  const collapsed = useWorkspace((s) => s.sidebarCollapsed);
  const toggle = useWorkspace((s) => s.toggleSidebar);
  const groups = useWorkspace((s) => s.collapsedGroups);
  const toggleGroup = useWorkspace((s) => s.toggleGroup);
  const match = useMatch("/cases/:number/*");
  const base = match ? `/cases/${encodeURIComponent(match.params.number ?? "")}` : "";

  return (
    <nav className={collapsed ? "sidebar collapsed" : "sidebar"} aria-label="Navigation">
      <div className="nav-section">
        {GLOBAL_NAV.map((i) => (
          <Item key={i.id} item={i} base="" collapsed={collapsed} />
        ))}
      </div>
      {match && (
        <div className="nav-section case-nav">
          {!collapsed && <div className="section-label nav-heading">Case</div>}
          {CASE_NAV.map((g) => (
            <div key={g.id} className="nav-group">
              {!collapsed && g.id !== "case" && (
                <button
                  type="button"
                  className="nav-group-head section-label"
                  aria-expanded={!groups[g.id]}
                  onClick={() => toggleGroup(g.id)}
                >
                  {groups[g.id] ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                  {g.label}
                </button>
              )}
              {(collapsed || !groups[g.id]) &&
                g.items.map((i) => <Item key={i.id} item={i} base={base} collapsed={collapsed} />)}
            </div>
          ))}
        </div>
      )}
      <div className="spacer" />
      <div className="nav-foot">
        <IconButton
          label={collapsed ? "Expand sidebar ([)" : "Collapse sidebar ([)"}
          icon={collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          onClick={toggle}
          tip="right"
        />
      </div>
    </nav>
  );
}
