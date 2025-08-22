// src/pages/Onboarding.jsx
import { Link } from "react-router-dom";

export default function Onboarding() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b0f1a] text-white">
      <div className="w-full max-w-md text-center space-y-8 p-8">
        <div className="space-y-3">
          <img src="/logo512.png" alt="SkillSwap" className="mx-auto h-20 w-20" />
          <h1 className="text-3xl font-bold">Welcome to SkillSwap</h1>
          <p className="opacity-80">Learn and teach skills with your local community.</p>
        </div>
        <div className="space-y-4">
          <Link className="block w-full py-3 rounded-lg bg-white text-black font-semibold" to="/register">
            Register
          </Link>
          <Link className="block w-full py-3 rounded-lg border border-white/30 font-semibold" to="/login">
            Log in
          </Link>
        </div>
      </div>
    </div>
  );
}
