// src/pages/Login.jsx
import { useState } from "react";
import { loginWithPassword, setAuthTokens } from "../lib/api";
import { useNavigate, Link } from "react-router-dom";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    setLoading(true);
    try {
      const { data } = await loginWithPassword({ email, password });
      // backend returns {accessToken, refreshToken, user}
      setAuthTokens({ token: data.accessToken, refreshToken: data.refreshToken });
      nav("/");
    } catch (e) {
      setErr(e?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b0f1a] text-white">
      <form onSubmit={submit} className="w-full max-w-md space-y-4 p-8 bg-white/5 rounded-xl border border-white/10">
        <h2 className="text-2xl font-bold text-center">Log in</h2>
        {err && <div className="p-3 rounded bg-red-500/20 border border-red-500/40">{err}</div>}
        <input className="w-full p-3 rounded bg-white/10 border border-white/20" placeholder="Email" type="email" value={email} onChange={(e)=>setEmail(e.target.value)} required />
        <input className="w-full p-3 rounded bg-white/10 border border-white/20" placeholder="Password" type="password" value={password} onChange={(e)=>setPassword(e.target.value)} required />
        <button disabled={loading} className="w-full py-3 rounded bg-white text-black font-semibold">
          {loading ? "Signing in..." : "Log in"}
        </button>
        <p className="text-center opacity-80">
          New here? <Link className="underline" to="/register">Create an account</Link>
        </p>
      </form>
    </div>
  );
}
