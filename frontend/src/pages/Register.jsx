// src/pages/Register.jsx
import { useState } from "react";
import { registerWithPassword, setAuthTokens } from "../lib/api";
import { useNavigate, Link } from "react-router-dom";

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    setLoading(true);
    try {
      const { data } = await registerWithPassword({ email, password, name });
      // backend returns {accessToken, refreshToken, user}
      setAuthTokens({ token: data.accessToken, refreshToken: data.refreshToken });
      nav("/");
    } catch (e) {
      setErr(e?.response?.data?.detail || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b0f1a] text-white">
      <form onSubmit={submit} className="w-full max-w-md space-y-4 p-8 bg-white/5 rounded-xl border border-white/10">
        <h2 className="text-2xl font-bold text-center">Create your account</h2>
        {err && <div className="p-3 rounded bg-red-500/20 border border-red-500/40">{err}</div>}
        <input className="w-full p-3 rounded bg-white/10 border border-white/20" placeholder="Name (optional)" value={name} onChange={(e)=>setName(e.target.value)} />
        <input className="w-full p-3 rounded bg-white/10 border border-white/20" placeholder="Email" type="email" value={email} onChange={(e)=>setEmail(e.target.value)} required />
        <input className="w-full p-3 rounded bg-white/10 border border-white/20" placeholder="Password (min 8)" type="password" value={password} onChange={(e)=>setPassword(e.target.value)} required />
        <button disabled={loading} className="w-full py-3 rounded bg-white text-black font-semibold">
          {loading ? "Creating..." : "Register"}
        </button>
        <p className="text-center opacity-80">
          Already have an account? <Link className="underline" to="/login">Log in</Link>
        </p>
      </form>
    </div>
  );
}
