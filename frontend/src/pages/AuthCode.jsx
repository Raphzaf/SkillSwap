import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Button } from "../components/ui/button";
import { Card, CardContent } from "../components/ui/card";
import { useToast } from "../components/ui/use-toast";
import { requestCode, verifyCode } from "../lib/api";

const maskEmail = (e) => {
  if (!e || !e.includes("@")) return e || "";
  const [n, d] = e.split("@");
  return (n?.[0] || "") + "***@" + d;
};

export default function AuthCode() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();

  const email = useMemo(() => {
    const p = new URLSearchParams(location.search);
    return (p.get("email") || localStorage.getItem("last_auth_email") || "").trim();
  }, [location.search]);

  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  // Init cooldown (30s) si l'utilisateur vient de demander un code
  useEffect(() => {
    const last = Number(localStorage.getItem("last_code_requested_at") || 0);
    if (!last) return;
    const elapsed = Math.floor((Date.now() - last) / 1000);
    const start = Math.max(0, 30 - elapsed);
    setCooldown(start);
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const id = setInterval(() => setCooldown((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(id);
  }, [cooldown]);

  // Auto-submit quand 6 chiffres sont saisis
  useEffect(() => {
    if (code.length === 6) {
      onVerify();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code]);

  const onVerify = async (e) => {
    e?.preventDefault();
    if (!email) {
      toast({ title: "Email manquant", description: "Revenez à l’étape précédente." });
      return;
    }
    if (!/^\d{6}$/.test(code)) {
      toast({ title: "Code invalide", description: "Entrez les 6 chiffres reçus par email." });
      return;
    }
    setBusy(true);
    try {
      const { data } = await verifyCode(email, code);
      // Stockage tokens
      localStorage.setItem("accessToken", data.accessToken);
      if (data.refreshToken) localStorage.setItem("refreshToken", data.refreshToken);
      toast({ title: "Bienvenue !", description: "Authentification réussie." });
      navigate("/");
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || "Erreur réseau";
      toast({ title: "Vérification échouée", description: String(msg) });
    } finally {
      setBusy(false);
    }
  };

  const onResend = async () => {
    if (!email) return;
    setBusy(true);
    try {
      await requestCode(email);
      localStorage.setItem("last_code_requested_at", String(Date.now()));
      setCooldown(30);
      toast({ title: "Code renvoyé", description: `Nouveau code envoyé à ${maskEmail(email)}.` });
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || "Erreur réseau";
      toast({ title: "Envoi impossible", description: String(msg) });
    } finally {
      setBusy(false);
    }
  };

  if (!email) {
    return (
      <div className="max-w-md mx-auto mt-10">
        <Card>
          <CardContent className="p-6 space-y-4">
            <h1 className="text-xl font-semibold">Code de vérification</h1>
            <p className="text-sm text-muted-foreground">
              Il manque l’email. <button className="underline" onClick={() => navigate("/auth/email")}>Retour</button>
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto mt-10">
      <Card>
        <CardContent className="p-6 space-y-4">
          <h1 className="text-2xl font-semibold">Entrez votre code</h1>
          <p className="text-sm text-muted-foreground">
            Un code à 6 chiffres a été envoyé à <span className="font-medium">{maskEmail(email)}</span>.
          </p>

          <form onSubmit={onVerify} className="space-y-3">
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="\d{6}"
              maxLength={6}
              placeholder="••••••"
              className="tracking-[0.6em] text-center text-2xl w-full rounded-md border px-3 py-3 focus:outline-none focus:ring"
              value={code}
              onChange={(e) => {
                const digits = e.target.value.replace(/\D/g, "").slice(0, 6);
                setCode(digits);
              }}
              autoFocus
            />
            <Button type="submit" disabled={busy || code.length !== 6} className="w-full">
              {busy ? "Vérification..." : "Valider"}
            </Button>
          </form>

          <div className="flex items-center justify-between text-sm">
            <button
              className="underline disabled:opacity-50"
              onClick={() => navigate(`/auth/email`)}
              disabled={busy}
            >
              Changer d’email
            </button>
            <button
              className="underline disabled:opacity-50"
              onClick={onResend}
              disabled={busy || cooldown > 0}
              title={cooldown > 0 ? `Réessayer dans ${cooldown}s` : "Renvoyer le code"}
            >
              {cooldown > 0 ? `Renvoyer (${cooldown}s)` : "Renvoyer le code"}
            </button>
          </div>

          <p className="text-xs text-muted-foreground">
            Pensez à vérifier vos spams. Le code expire après quelques minutes.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
