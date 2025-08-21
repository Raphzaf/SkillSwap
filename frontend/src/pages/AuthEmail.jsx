import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../components/ui/button";
import { Card, CardContent } from "../components/ui/card";
import { useToast } from "../components/ui/use-toast";
import { requestCode } from "../lib/api";

// Simple helper
const isEmail = (v) => /^\S+@\S+\.\S+$/.test(v);

export default function AuthEmail() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);

  // Si un ancien email a été utilisé, pré-remplir
  useEffect(() => {
    const last = localStorage.getItem("last_auth_email");
    if (last) setEmail(last);
  }, []);

  const onSend = async (e) => {
    e?.preventDefault();
    if (!isEmail(email)) {
      toast({ title: "Email invalide", description: "Merci de saisir un email valide." });
      return;
    }
    setBusy(true);
    try {
      await requestCode(email);
      localStorage.setItem("last_auth_email", email);
      // pour un petit UX bonus côté /code
      localStorage.setItem("last_code_requested_at", String(Date.now()));
      toast({ title: "Code envoyé", description: "Vérifiez votre boîte mail." });
      navigate(`/auth/code?email=${encodeURIComponent(email)}`);
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || "Erreur réseau";
      toast({ title: "Envoi impossible", description: String(msg) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10">
      <Card>
        <CardContent className="p-6 space-y-4">
          <h1 className="text-2xl font-semibold">Connexion / Inscription</h1>
          <p className="text-sm text-muted-foreground">
            Saisissez votre email pour recevoir un code à 6 chiffres. Pas de mot de passe.
          </p>

          <form onSubmit={onSend} className="space-y-3">
            <input
              type="email"
              className="w-full rounded-md border px-3 py-2 focus:outline-none focus:ring"
              placeholder="votre@email.tld"
              value={email}
              onChange={(e) => setEmail(e.target.value.trim())}
              autoComplete="email"
              required
            />
            <Button type="submit" disabled={!isEmail(email) || busy} className="w-full">
              {busy ? "Envoi..." : "Recevoir un code"}
            </Button>
          </form>

          <p className="text-xs text-muted-foreground">
            En continuant, vous acceptez le traitement de votre email pour l’authentification.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
