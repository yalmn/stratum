// HTTP-Zugriff auf /api/v1. Die Sitzung steckt im HttpOnly-Cookie, das der
// Server bei der Anmeldung setzt; das Token selbst sieht die Oberfläche nie.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method: options.method ?? "GET",
    credentials: "same-origin",
    headers: options.body === undefined ? undefined : { "Content-Type": "application/json" },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  let content: unknown = null;
  try {
    content = text ? JSON.parse(text) : null;
  } catch {
    content = null;
  }
  if (!response.ok) {
    const message =
      content && typeof content === "object" && "fehler" in content
        ? String((content as { fehler: unknown }).fehler)
        : `HTTP ${response.status}`;
    throw new ApiError(response.status, message);
  }
  return content as T;
}

export function isUnauthorized(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}
