// src/lib/api.js
import axios from "axios";

/* ---------- Base URL robuste CRA + Vite ---------- */
function readEnvBackend() {
  // Vite
  const vite =
    typeof import.meta !== "undefined" &&
    import.meta.env &&
    import.meta.env.VITE_BACKEND_URL;

  // CRA / Node
  const cra = typeof process !== "undefined"
    ? process.env.REACT_APP_BACKEND_URL
    : undefined;

  return vite || cra || "http://127.0.0.1:8001"; // fallback dev
}

const RAW_BASE = readEnvBackend();
export const BASE_URL = `${String(RAW_BASE).replace(/\/+$/, "")}/api`;

/* ---------- Device ID (auth dev côté backend) ---------- */
export function getDeviceId() {
  try {
    let id = localStorage.getItem("ss_device_id");
    if (!id) {
      const uuid =
        (typeof crypto !== "undefined" && crypto.randomUUID)
          ? crypto.randomUUID()
          : Date.now().toString(36) + Math.random().toString(36).slice(2);
      id = `web-${uuid}`;
      localStorage.setItem("ss_device_id", id);
    }
    return id;
  } catch {
    return "web-fallback-id";
  }
}

/* ---------- (Optionnel) JWT local ---------- */
export function getToken() { return localStorage.getItem("ss_token") || null; }
export function setAuthTokens({ token, refreshToken }) {
  if (token) localStorage.setItem("ss_token", token);
  if (refreshToken) localStorage.setItem("ss_refresh", refreshToken);
}
export function clearAuthTokens() {
  localStorage.removeItem("ss_token");
  localStorage.removeItem("ss_refresh");
}

/* ---------- Axios instance ---------- */
const api = axios.create({
  baseURL: BASE_URL,          // toujours ABSOLU (backend), plus de /api vers 5173 !
  timeout: 15000,
  withCredentials: false,
});

api.interceptors.request.use((config) => {
  const headers = config.headers || {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  headers["X-Device-Id"] = getDeviceId();
  headers["Accept"] = headers["Accept"] || "application/json";
  config.headers = headers;
  return config;
});

// Rafraîchissement désactivé par défaut
const USE_REFRESH = false;
let refreshing = null;

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const status = error?.response?.status;
    const original = error?.config || {};
    if (USE_REFRESH && status === 401 && !original._retry) {
      original._retry = true;
      try {
        const rt = localStorage.getItem("ss_refresh");
        if (!refreshing) {
          refreshing = fetch(`${BASE_URL}/auth/refresh`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refreshToken: rt }),
          })
            .then((r) => r.json())
            .finally(() => { refreshing = null; });
        }
        const data = await refreshing;
        if (data?.accessToken) {
          setAuthTokens({ token: data.accessToken });
          original.headers = original.headers || {};
          original.headers["Authorization"] = `Bearer ${data.accessToken}`;
          return api(original);
        }
      } catch {}
      clearAuthTokens();
    }
    return Promise.reject(error);
  }
);

/* ---------- Idempotency helper ---------- */
export function newIdem() {
  const rand = Math.random().toString(36).slice(2, 8);
  const now = Date.now();
  return `idem-${now}-${rand}`;
}
function withIdem(config = {}) {
  const key = newIdem();
  return {
    ...(config || {}),
    headers: { ...(config.headers || {}), "Idempotency-Key": key },
  };
}

/* ==================== API ==================== */
export const registerWithPassword = (body) => api.post("/auth/register", body);
export const loginWithPassword    = (body) => api.post("/auth/login", body);

export async function requestCode(email) { return (await api.post("/auth/request-code", { email })).data; }
export async function verifyCode(email, code) { return (await api.post("/auth/verify-code", { email, code })).data; }

export async function getMe() { return (await api.get("/me")).data; }
export async function updateMe(payload) { return (await api.put("/me", payload)).data; }
export async function updateSettings(payload) { return (await api.put("/me/settings", payload)).data; }
export async function exportMyData() { return (await api.get("/me/export")).data; }
export async function deleteMyAccount() { return (await api.delete("/me")).data; }

export async function getCandidates(cursor = 0, limit = 10) {
  try {
    return (await api.get("/candidates", { params: { cursor, limit } })).data;
  } catch (e) {
    if (e?.response?.status === 404) {
      return (await api.get("/deck", { params: { limit } })).data;
    }
    throw e;
  }
}
export async function sendSwipe(targetUserId, action = "like") {
  return (await api.post("/swipe", { targetUserId, action }, withIdem())).data;
}
export async function getMatches() { return (await api.get("/matches")).data; }
export async function listMessages(matchId, cursor = 0, limit = 50) {
  return (await api.get(`/matches/${matchId}/messages`, { params: { cursor, limit } })).data;
}
export async function sendMessage(matchId, payload) {
  const body = typeof payload === "string" ? { text: payload } : { text: payload?.text };
  return (await api.post(`/matches/${matchId}/messages`, body)).data;
}
export async function listSessions(matchId) {
  try { return (await api.get("/sessions", { params: { matchId } })).data; }
  catch (e) { if (e?.response?.status === 404) return { sessions: [] }; throw e; }
}
export async function createSession(payload) { return (await api.post("/sessions", payload, withIdem())).data; }
export async function updateSession(sessionId, status) { return (await api.patch(`/sessions/${sessionId}`, { status })).data; }
export function downloadSessionIcs(sessionId) { return `${BASE_URL}/sessions/${sessionId}/ics`; }
export async function triggerSessionIcsDownload(sessionId) {
  const res = await api.get(`/sessions/${sessionId}/ics`, { responseType: "blob" });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = url; a.download = "skillswap.ics"; a.click();
  URL.revokeObjectURL(url);
}
export async function createRating(payload) { return (await api.post("/ratings", payload, withIdem())).data; }
export async function getMyRatingForSession(sessionId) {
  try { return (await api.get(`/ratings/session/${sessionId}/my`)).data; }
  catch (e) { if (e?.response?.status === 404) return null; throw e; }
}

export default api;
