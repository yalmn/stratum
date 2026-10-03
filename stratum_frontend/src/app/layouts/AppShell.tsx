import { useEffect, useMemo, useRef, type ReactNode } from "react";
import { useMatch, useNavigate } from "react-router-dom";
import { Briefcase, Clock, LayoutDashboard, Palette as PaletteIcon, PanelLeft, Plus, Upload } from "lucide-react";
import { CommandPalette, type PaletteItem } from "../../components/ui/Overlay";
import { ContextDrawer } from "../../features/drawer/ContextDrawer";
import { JobWatcher } from "../../features/jobs/live";
import { useCases } from "../../lib/api/queries";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../detail";
import { CASE_ITEMS, GLOBAL_NAV } from "../navigation";
import { useWorkspace } from "../store";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

function typing(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null;
  return !!t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));
}

/**
 * Tastenkürzel (Abschnitt 32): Mod+K und / öffnen die Palette, G gefolgt
 * von einem Buchstaben wechselt die Ansicht, Esc schließt den Drawer,
 * [ klappt die Sidebar.
 */
function useShortcuts(caseBase: string | null) {
  const navigate = useNavigate();
  const setPalette = useWorkspace((s) => s.setPalette);
  const toggleSidebar = useWorkspace((s) => s.toggleSidebar);
  const { detail, close } = useDetail();
  const pendingG = useRef<number>(0);

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette(true);
        return;
      }
      if (typing(e) || e.metaKey || e.ctrlKey) {
        return;
      }
      // [ liegt auf deutschen Mac-Tastaturen auf Option+5.
      if (e.key === "[") {
        toggleSidebar();
        return;
      }
      if (e.altKey) {
        return;
      }
      if (e.key === "/") {
        e.preventDefault();
        setPalette(true);
      } else if (e.key === "Escape" && detail && !useWorkspace.getState().paletteOpen) {
        close();
      } else if (e.key === "g" && !pendingG.current) {
        pendingG.current = window.setTimeout(() => (pendingG.current = 0), 900);
      } else if (pendingG.current) {
        window.clearTimeout(pendingG.current);
        pendingG.current = 0;
        const k = e.key.toLowerCase();
        const global = GLOBAL_NAV.find((i) => i.key === k && !i.planned);
        const local = CASE_ITEMS.find((i) => i.key === k && !i.planned);
        if (local && caseBase) {
          navigate(`${caseBase}/${local.path}`);
        } else if (global?.path) {
          navigate(global.path);
        }
      }
    };
    window.addEventListener("keydown", down);
    return () => window.removeEventListener("keydown", down);
  }, [caseBase, close, detail, navigate, setPalette, toggleSidebar]);
}

function GlobalPalette({ caseBase, caseNumber }: { caseBase: string | null; caseNumber?: string }) {
  const open = useWorkspace((s) => s.paletteOpen);
  const setPalette = useWorkspace((s) => s.setPalette);
  const recent = useWorkspace((s) => s.recent);
  const navigate = useNavigate();
  const cases = useCases();
  const { can } = useSession();

  const items = useMemo<PaletteItem[]>(() => {
    const list: PaletteItem[] = [];
    for (const r of recent) {
      list.push({
        id: `recent-${r.id}`,
        group: "Recent",
        label: r.label,
        hint: r.hint,
        icon: <Clock />,
        run: () => navigate(`/cases/${encodeURIComponent(r.id)}/overview`),
      });
    }
    if (caseBase && caseNumber) {
      for (const i of CASE_ITEMS) {
        list.push({
          id: `case-${i.id}`,
          group: `Go to · ${caseNumber}`,
          label: `Open ${i.label}`,
          hint: i.planned ?? (i.key ? `G ${i.key.toUpperCase()}` : undefined),
          icon: i.icon,
          disabled: !!i.planned,
          keywords: "open go view",
          run: () => navigate(`${caseBase}/${i.path}`),
        });
      }
      if (can("evidence.import")) {
        list.push({
          id: "add-evidence",
          group: "Actions",
          label: "Add evidence from the case folder",
          icon: <Upload />,
          run: () => navigate(`${caseBase}/evidence?add=1`),
        });
      }
    }
    if (can("case.create")) {
      list.push({ id: "new-case", group: "Actions", label: "New case", icon: <Plus />, run: () => navigate("/cases?new=1") });
    }
    list.push({
      id: "toggle-sidebar",
      group: "Actions",
      label: "Toggle sidebar",
      hint: "[",
      icon: <PanelLeft />,
      run: () => useWorkspace.getState().toggleSidebar(),
    });
    for (const c of cases.data ?? []) {
      list.push({
        id: `open-${c.id}`,
        group: "Cases",
        label: `open ${c.case_number}`,
        hint: c.title,
        icon: <Briefcase />,
        keywords: c.title,
        run: () => navigate(`/cases/${encodeURIComponent(c.case_number)}/overview`),
      });
    }
    for (const g of GLOBAL_NAV) {
      list.push({
        id: `global-${g.id}`,
        group: "Navigate",
        label: `go to ${g.label}`,
        hint: g.planned,
        icon: g.icon,
        disabled: !!g.planned,
        run: () => g.path && navigate(g.path),
      });
    }
    list.push({
      id: "design",
      group: "Navigate",
      label: "go to Design System",
      icon: <PaletteIcon />,
      run: () => navigate("/dev/design-system"),
    });
    list.push({
      id: "overview-all",
      group: "Navigate",
      label: "go to Cases overview",
      icon: <LayoutDashboard />,
      run: () => navigate("/cases"),
    });
    return list;
  }, [recent, caseBase, caseNumber, cases.data, can, navigate]);

  return open ? <CommandPalette items={items} onClose={() => setPalette(false)} /> : null;
}

export function AppShell({ children }: { children: ReactNode }) {
  const match = useMatch("/cases/:number/*");
  const caseNumber = match?.params.number;
  const caseBase = caseNumber ? `/cases/${encodeURIComponent(caseNumber)}` : null;
  const collapsed = useWorkspace((s) => s.sidebarCollapsed);
  const { detail } = useDetail();
  useShortcuts(caseBase);

  return (
    <div className={collapsed ? "shell sidebar-collapsed" : "shell"}>
      <Topbar />
      <Sidebar />
      <main className={detail ? "workspace with-drawer" : "workspace"}>
        <div className="workspace-main">{children}</div>
        {detail && <ContextDrawer detail={detail} caseNumber={caseNumber} />}
      </main>
      <GlobalPalette caseBase={caseBase} caseNumber={caseNumber} />
      <JobWatcher />
    </div>
  );
}
