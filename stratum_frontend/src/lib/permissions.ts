import { createContext, useContext } from "react";
import type { Me, Permission } from "./api/types";

export interface Session {
  me: Me;
  can: (p: Permission) => boolean;
}

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) {
    throw new Error("useSession outside the session");
  }
  return s;
}

/** Superadmins haben jedes Recht; sonst die Rechte aus ihren Rollen. */
export function sessionFor(me: Me): Session {
  return { me, can: (p) => me.konto.superadmin || me.rechte.includes(p) };
}
