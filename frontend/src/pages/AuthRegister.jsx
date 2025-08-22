import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { registerWithPassword } from "../lib/api";
import { Button } from "../components/ui/button";
import { Card, CardContent } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { useToast } from "../components/ui/use-toast";

export default function AuthRegister() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [pwd, setPwd] = useState("");
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    if (!email || !pwd) {
      toast({ title: "Missing fields", description: "Email and password are required." });
      return;
    }
    setBusy(true);
    try {
      const { data } = await registerWithPassword({ email, password: pwd, name });
      localStorage.setItem("accessToken", data.accessToken);
      localStorage.setItem("refreshToken", data.refreshToken);
      navigate("/");
    } catch (err) {
      toast({ title: "Register failed", description: err?.response?.data?.detail || err?.message || "Error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/20 p-4">
      <Card className="w-full max-w-md">
        <CardContent className="p-6">
          <h1 className="text-xl font-semibold mb-4">Create your account</h1>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="name">Name (optional)</Label>
              <Input id="name" placeholder="Jane" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" required placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pwd">Password</Label>
              <Input id="pwd" type="password" required minLength={8} placeholder="At least 8 characters" value={pwd} onChange={(e) => setPwd(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy} className="w-full">
              {busy ? "Creating..." : "Register"}
            </Button>
          </form>

          <p className="text-sm text-muted-foreground mt-4">
            Already have an account?{" "}
            <Link to="/auth/login" className="underline">Log in</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
