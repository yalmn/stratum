// Navigation an einer Stelle: Sidebar, Command Palette und Tastenkürzel
// lesen dieselbe Liste. Ansichten ohne Backend sind sichtbar, aber gesperrt
// und nennen die Ausbaustufe, in der sie kommen.

import type { ReactNode } from "react";
import {
  Activity,
  BookOpen,
  Boxes,
  Briefcase,
  FileSearch,
  FileText,
  Flag,
  FlaskConical,
  FolderTree,
  Globe,
  HardDrive,
  LayoutDashboard,
  MessageSquare,
  Plug,
  Radar,
  ScrollText,
  Search,
  Users,
  Waypoints,
  Workflow,
} from "lucide-react";

export interface NavItem {
  id: string;
  label: string;
  icon: ReactNode;
  /** Pfad relativ zum Fall bzw. absolut für globale Ziele. */
  path?: string;
  /** Tastenfolge nach `G`. */
  key?: string;
  /** Ausbaustufe, falls noch nicht verfügbar. */
  planned?: string;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

const INVESTIGATION = "Planned: Investigation Core";
const OPERATIONS = "Planned: Operational Layer";
const INTELLIGENCE = "Planned: Intelligence";
const ADVANCED = "Planned: Advanced Forensics";

export const GLOBAL_NAV: NavItem[] = [
  { id: "cases", label: "Cases", icon: <Briefcase />, path: "/cases", key: "c" },
  { id: "intel", label: "Threat Intelligence", icon: <Radar />, planned: INTELLIGENCE },
  { id: "playbooks", label: "Playbooks", icon: <Workflow />, planned: OPERATIONS },
  { id: "search", label: "Global Search", icon: <Search />, planned: INVESTIGATION },
  { id: "knowledge", label: "Knowledge", icon: <BookOpen />, planned: INTELLIGENCE },
  { id: "connectors", label: "Connectors", icon: <Plug />, planned: INTELLIGENCE },
];

export const CASE_NAV: NavGroup[] = [
  {
    id: "case",
    label: "Case",
    items: [
      { id: "overview", label: "Overview", icon: <LayoutDashboard />, path: "overview", key: "o" },
      { id: "war-room", label: "War Room", icon: <MessageSquare />, key: "w", planned: OPERATIONS },
    ],
  },
  {
    id: "evidence",
    label: "Evidence",
    items: [
      { id: "evidence", label: "Evidence", icon: <HardDrive />, path: "evidence", key: "e" },
      { id: "explorer", label: "Explorer", icon: <FolderTree />, key: "x", planned: INVESTIGATION },
      { id: "artifacts", label: "Artifacts", icon: <Boxes />, planned: INVESTIGATION },
    ],
  },
  {
    id: "investigation",
    label: "Investigation",
    items: [
      { id: "search", label: "Search", icon: <FileSearch />, key: "s", planned: INVESTIGATION },
      { id: "timeline", label: "Timeline", icon: <Activity />, key: "t", planned: INVESTIGATION },
      { id: "graph", label: "Graph", icon: <Waypoints />, key: "g", planned: INVESTIGATION },
      { id: "entities", label: "Entities", icon: <Users />, key: "n", planned: INVESTIGATION },
      { id: "findings", label: "Findings", icon: <Flag />, key: "f", planned: INVESTIGATION },
    ],
  },
  {
    id: "tools",
    label: "Tools",
    items: [
      { id: "reconstruction", label: "Reconstruction", icon: <FlaskConical />, planned: ADVANCED },
      { id: "case-playbooks", label: "Playbooks", icon: <Workflow />, planned: OPERATIONS },
      { id: "case-intel", label: "Threat Intelligence", icon: <Globe />, planned: INTELLIGENCE },
      { id: "reports", label: "Reports", icon: <FileText />, planned: OPERATIONS },
      { id: "audit", label: "Audit", icon: <ScrollText />, key: "a", planned: OPERATIONS },
    ],
  },
];

export const CASE_ITEMS: NavItem[] = CASE_NAV.flatMap((g) => g.items);
