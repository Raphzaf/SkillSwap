// src/lib/api.js
import axios from "axios";

/* ---------- Base URL ---------- */
const RAW_BASE = process.env.REACT_APP_BACKEND_URL || "http://localhost:8001";
export const BASE_URL = `${RAW_BASE.replace(/\/+$/, "")}/api`;

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
export function getToken() {
  return localStorage.getItem("ss_token") || null;
}
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
  baseURL: BASE_URL,
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

// Si un jour tu actives /auth/refresh côté backend, passe USE_REFRESH à true
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
            .finally(() => {
              refreshing = null;
            });
        }
        const data = await refreshing;
        if (data?.token) {
          setAuthTokens({ token: data.token });
          original.headers = original.headers || {};
          original.headers["Authorization"] = `Bearer ${data.token}`;
          return api(original);
        }
      } catch {
        /* ignore */
      }
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

/* --- Auth (optionnel / si backend activé) --- */
export async function requestCode(email) {
  const res = await api.post("/auth/request-code", { email });
  return res.data;
}
export async function verifyCode(email, code) {
  const res = await api.post("/auth/verify-code", { email, code });
  return res.data;
}

/* --- Me --- */
export async function getMe() {
  const res = await api.get("/me");
  return res.data;
}
export async function updateMe(payload) {
  const res = await api.put("/me", payload);
  return res.data;
}
export async function updateSettings(payload) {
  const res = await api.put("/me/settings", payload);
  return res.data;
}
export async function exportMyData() {
  // Si non implémenté côté backend: 404
  const res = await api.get("/me/export");
  return res.data;
}
export async function deleteMyAccount() {
  // Si non implémenté côté backend: 404
  const res = await api.delete("/me");
  return res.data;
}

/* --- Discovery (deck / swipe) --- */
// Essaie /candidates (si tu l’ajoutes plus tard), puis fallback /deck (implémenté aujourd’hui)
export async function getCandidates(cursor = 0, limit = 10) {
  try {
    const res = await api.get("/candidates", { params: { cursor, limit } });
    return res.data;
  } catch (e) {
    if (e?.response?.status === 404) {
      const res = await api.get("/deck", { params: { limit } });
      return res.data; // { profiles: [...] }
    }
    throw e;
  }
}
export async function sendSwipe(targetUserId, action = "like") {
  const res = await api.post("/swipe", { targetUserId, action }, withIdem());
  return res.data; // { matched: boolean, matchId? }
}

/* --- Matches & Messages --- */
export async function getMatches() {
  const res = await api.get("/matches");
  return res.data; // { matches: [...] }
}
export async function listMessages(matchId, cursor = 0, limit = 50) {
  const res = await api.get(`/matches/${matchId}/messages`, {
    params: { cursor, limit },
  });
  return res.data; // { messages: [...] }
}
export async function sendMessage(matchId, payload) {
  // backend attend { text }, et renvoie { message: {...} }
  const body =
    typeof payload === "string" ? { text: payload } : { text: payload?.text };
  const res = await api.post(`/matches/${matchId}/messages`, body);
  return res.data; // { message: {...} }
}

/* --- Sessions --- */
// GET /sessions n’est pas implémenté dans le backend actuel.
// On tente, et on renvoie un fallback vide si 404 (pour ne pas casser l’UI).
export async function listSessions(matchId) {
  try {
    const res = await api.get("/sessions", { params: { matchId } });
    return res.data;
  } catch (e) {
    if (e?.response?.status === 404) return { sessions: [] };
    throw e;
  }
}
export async function createSession(payload) {
  const res = await api.post("/sessions", payload, withIdem());
  return res.data; // { session: {...} }
}
export async function updateSession(sessionId, status) {
  const res = await api.patch(`/sessions/${sessionId}`, { status });
  return res.data; // { session: {...} }
}
// URL directe (si tu veux faire window.location = ...)
export function downloadSessionIcs(sessionId) {
  return `${BASE_URL}/sessions/${sessionId}/ics`;
}
// Helper pour déclencher un vrai téléchargement côté front
export async function triggerSessionIcsDownload(sessionId) {
  const res = await api.get(`/sessions/${sessionId}/ics`, {
    responseType: "blob",
  });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = "skillswap.ics";
  a.click();
  URL.revokeObjectURL(url);
}

/* --- Ratings --- */
export async function createRating(payload) {
  const res = await api.post("/ratings", payload, withIdem());
  return res.data; // { rating: {...} }
}
// Si non implémenté côté backend, renvoie null plutôt que de jeter
export async function getMyRatingForSession(sessionId) {
  try {
    const res = await api.get(`/ratings/session/${sessionId}/my`);
    return res.data;
  } catch (e) {
    if (e?.response?.status === 404) return null;
    throw e;
  }
}

export default api;
