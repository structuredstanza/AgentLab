const TOKEN_KEY = "m1nervac0nsole_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 days (in seconds)

// The cookie is a presence marker for the Next.js route guard (src/proxy.ts),
// which runs on the server and cannot read localStorage. It deliberately does
// not carry the JWT: a script-readable cookie is a second copy of the session
// credential for any XSS, extension or same-origin page. The JWT stays in
// localStorage and travels as a bearer header. SSE streams use the HttpOnly
// m1nervac0nsole_stream cookie the backend sets at login (a different name, so
// this marker can never overwrite it), and only fall back to ?token= when the
// stream is cross-origin.
const COOKIE_MARKER = "1";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo: no real login; returns a fake token so the route guard lets the user through directly to the main interface.
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // Synchronously write the marker so the Next.js middleware can read it on the server side
    document.cookie = `${TOKEN_KEY}=${COOKIE_MARKER}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
    // The backend's HttpOnly stream cookie is not script-writable, so ask the
    // server to drop its copy: a logged-out browser must keep no credential.
    // Fire and forget; the caller navigates away immediately.
    try {
      void fetch("/api/auth/logout", { method: "POST", keepalive: true }).catch(() => {
        // Best effort: the stream cookie expires with the token regardless.
      });
    } catch {
      // No fetch (SSR or a test shim): the cookie still expires with the token.
    }
  },

  // Parse the current user from the sub field of the JWT payload, for display only; no signature verification is performed.
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "minerva";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};
