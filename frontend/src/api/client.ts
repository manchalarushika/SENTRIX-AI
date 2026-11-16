import axios, { AxiosError } from "axios";

const BASE = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ?? "";

// Analyst identity and optional API key are kept in the browser only.
const store = {
  get(key: string): string {
    try {
      return window.localStorage.getItem(key) ?? "";
    } catch {
      return "";
    }
  },
  set(key: string, value: string) {
    try {
      if (value) window.localStorage.setItem(key, value);
      else window.localStorage.removeItem(key);
    } catch {
      /* storage unavailable - keep in-memory defaults */
    }
  },
};

export const session = {
  get actor() {
    return store.get("sentrix.actor") || "soc-analyst";
  },
  set actor(v: string) {
    store.set("sentrix.actor", v.trim());
  },
  get apiKey() {
    return store.get("sentrix.apiKey");
  },
  set apiKey(v: string) {
    store.set("sentrix.apiKey", v.trim());
  },
};

export const http = axios.create({ baseURL: `${BASE}/api`, timeout: 60000 });

http.interceptors.request.use((cfg) => {
  cfg.headers.set("X-Actor", session.actor);
  if (session.apiKey) cfg.headers.set("X-API-Key", session.apiKey);
  return cfg;
});

export function errorMessage(err: unknown): string {
  const e = err as AxiosError<any>;
  const d = e?.response?.data;
  if (d?.errors?.length) return `${d.detail}: ${d.errors.map((x: any) => `${x.loc?.slice(-1)[0]} ${x.msg}`).join("; ")}`;
  if (typeof d?.detail === "string") return d.detail;
  if (d?.detail?.message) return d.detail.message;
  if (e?.response?.status === 401) return "Unauthorized - set the API key in Settings";
  if (e?.code === "ERR_NETWORK") return "Backend unreachable - is the API running on port 8000?";
  return e?.message ?? "Unexpected error";
}

export async function get<T>(url: string, params?: Record<string, unknown>): Promise<T> {
  const clean = params
    ? Object.fromEntries(
        Object.entries(params)
          .map(([k, v]) => [k, Array.isArray(v) ? v.join(",") : v])
          .filter(([, v]) => v !== undefined && v !== null && v !== ""),
      )
    : undefined;
  return (await http.get<T>(url, { params: clean })).data;
}

export async function post<T>(url: string, body?: unknown, params?: Record<string, unknown>): Promise<T> {
  return (await http.post<T>(url, body, { params })).data;
}

export async function put<T>(url: string, body?: unknown): Promise<T> {
  return (await http.put<T>(url, body)).data;
}

export async function patch<T>(url: string, body?: unknown): Promise<T> {
  return (await http.patch<T>(url, body)).data;
}

export async function del<T>(url: string): Promise<T> {
  return (await http.delete<T>(url)).data;
}

export async function upload<T>(url: string, file: File, params?: Record<string, unknown>): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  return (await http.post<T>(url, form, { params })).data;
}

export async function download(url: string, params: Record<string, unknown>, filename: string) {
  const res = await http.get(url, { params, responseType: "blob" });
  const href = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(href);
}

export function wsUrl(): string {
  if (BASE) return BASE.replace(/^http/, "ws") + "/ws/live";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws/live`;
}
