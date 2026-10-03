// Lokaler Arbeitsplatz-Zustand (Zustand): Navigation, Bereichsgrößen,
// zuletzt Geöffnetes, Benachrichtigungen. Serverdaten liegen nicht hier,
// sondern im Cache von TanStack Query. Vorlieben bleiben im Browser
// gespeichert; Benachrichtigungen gelten nur für die laufende Sitzung.

import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

export interface RecentItem {
  kind: "case";
  id: string;
  label: string;
  hint?: string;
}

export interface Notification {
  id: string;
  title: string;
  text: string;
  tone: "info" | "success" | "warning" | "danger";
  at: string;
  link?: string;
  read: boolean;
}

interface WorkspaceState {
  sidebarCollapsed: boolean;
  collapsedGroups: Record<string, boolean>;
  paneSizes: Record<string, number>;
  recent: RecentItem[];
  paletteOpen: boolean;
  notifications: Notification[];
  toggleSidebar: () => void;
  toggleGroup: (g: string) => void;
  setPaneSize: (id: string, size: number) => void;
  remember: (item: RecentItem) => void;
  setPalette: (open: boolean) => void;
  notify: (n: Omit<Notification, "id" | "at" | "read">) => void;
  markRead: () => void;
}

export const useWorkspace = create<WorkspaceState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      collapsedGroups: {},
      paneSizes: {},
      recent: [],
      paletteOpen: false,
      notifications: [],
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      toggleGroup: (g) => set((s) => ({ collapsedGroups: { ...s.collapsedGroups, [g]: !s.collapsedGroups[g] } })),
      setPaneSize: (id, size) => set((s) => ({ paneSizes: { ...s.paneSizes, [id]: size } })),
      remember: (item) =>
        set((s) => ({
          recent: [item, ...s.recent.filter((r) => !(r.kind === item.kind && r.id === item.id))].slice(0, 8),
        })),
      setPalette: (open) => set({ paletteOpen: open }),
      notify: (n) =>
        set((s) => ({
          notifications: [
            { ...n, id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, at: new Date().toISOString(), read: false },
            ...s.notifications,
          ].slice(0, 30),
        })),
      markRead: () => set((s) => ({ notifications: s.notifications.map((n) => ({ ...n, read: true })) })),
    }),
    {
      name: "stratum.workspace",
      storage: createJSONStorage(() => localStorage),
      partialize: (s) => ({
        sidebarCollapsed: s.sidebarCollapsed,
        collapsedGroups: s.collapsedGroups,
        paneSizes: s.paneSizes,
        recent: s.recent,
      }),
    },
  ),
);
