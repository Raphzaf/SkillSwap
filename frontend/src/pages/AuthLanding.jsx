// src/pages/auth/AuthLanding.jsx
import React from "react";
import { useNavigate } from "react-router-dom";

export default function AuthLanding() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-6">
      <div className="w-full max-w-md bg-white rounded-2xl shadow p-8 text-center space-y-6">
        <img
          src="/public/favicon.svg"
          alt="SkillSwap"
          className="w-20 h-20 mx-auto"
        />
        <h1 className="text-2xl font-semibold">Welcome to SkillSwap</h1>
        <p className="text-sm text-gray-500">
          Learn from others. Teach what you love.
        </p>
        <div className="flex flex-col gap-3">
          <button
            onClick={() => navigate("/auth/register")}
            className="w-full py-3 rounded-xl bg-black text-white font-medium hover:opacity-90"
          >
            Create an account
          </button>
          <button
            onClick={() => navigate("/auth/login")}
            className="w-full py-3 rounded-xl border font-medium hover:bg-gray-50"
          >
            Log in
          </button>
        </div>
      </div>
    </div>
  );
}
