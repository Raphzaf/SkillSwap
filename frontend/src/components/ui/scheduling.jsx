import React, { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "./dialog";
import { Button } from "./button";
import { Input } from "./input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./select";
import { Card, CardContent } from "./card";
import { Skeleton } from "./skeleton";
import { Badge } from "./badge";
// shadcn useToast est dans le même dossier ui
import { useToast } from "./use-toast";

// Ces imports sortent du dossier "ui" vers "src"
import { CORAL } from "../../mock";
import {
  createSession,  
  listSessions,
  updateSession,
  downloadSessionIcs,
  createRating,
  getMyRatingForSession,
} from "../../lib/api";

/* -------------------- SessionFormDialog -------------------- */

export function SessionFormDialog({ open, onOpenChange, matchId, onCreated }) {
  const { toast } = useToast();
  const [start, setStart] = useState("");
  const [duration, setDuration] = useState(60);
  const [locType, setLocType] = useState("online");
  const [locValue, setLocValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (!open) return;
    if (cooldown > 0) {
      const t = setTimeout(() => setCooldown((x) => x - 1), 1000);
      return () => clearTimeout(t);
    }
  }, [cooldown, open]);

  const submit = async () => {
    if (!start || !locValue) {
      toast({ title: "Champs requis", description: "Merci de renseigner la date et le lieu/lien." });
      return;
    }

    // ✅ Garde-fous côté front, alignés avec le backend
    const MIN_OFFSET_MIN = 10; // mets 1 si tu as assoupli la règle côté back pour les tests
    const startDate = new Date(start);
    const diffMin = (startDate.getTime() - Date.now()) / 60000;
    if (diffMin < MIN_OFFSET_MIN) {
      toast({ title: "Horaire trop proche", description: `Choisis un début ≥ ${MIN_OFFSET_MIN} minutes.` });
      return;
    }
    const dur = Number(duration) || 60;
    if (![30, 60, 90].includes(dur)) {
      toast({ title: "Durée invalide", description: "Durée autorisée : 30, 60 ou 90 minutes." });
      return;
    }
    if (locType === "online" && !/^https:\/\//.test(locValue)) {
      toast({ title: "Lien invalide", description: "Pour une visio, l'URL doit commencer par https://." });
      return;
    }
    if (locType === "in_person" && (locValue || "").length > 80) {
      toast({ title: "Adresse trop longue", description: "Maximum 80 caractères." });
      return;
    }

    setSaving(true);
    try {
      const payload = {
        matchId,
        startAt: startDate.toISOString(),
        durationMin: dur,
        locationType: locType,
        locationValue: locValue,
      };
      await createSession(payload);
      toast({ title: "Proposition envoyée" });
      onCreated?.();
      onOpenChange(false);
      setCooldown(30);
      // reset léger
      setLocValue("");
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Erreur d'envoi";
      toast({ title: "Erreur", description: msg });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Proposer un créneau</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <div className="text-sm mb-1">Date & heure (Asia/Jerusalem)</div>
            <Input
              type="datetime-local"
              value={start}
              onChange={(e) => setStart(e.target.value)}
              className="h-11"
            />
          </div>
          <div>
            <div className="text-sm mb-1">Durée (min)</div>
            <Input
              type="number"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              className="h-11"
              min={30}
              max={90}
              step={30}
            />
          </div>
          <div>
            <div className="text-sm mb-1">Type</div>
            <Select value={locType} onValueChange={setLocType}>
              <SelectTrigger className="h-11">
                <SelectValue placeholder="Choisir" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="online">En ligne</SelectItem>
                <SelectItem value="in_person">En personne</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <div className="text-sm mb-1">Lien visio ou lieu</div>
            <Input
              value={locValue}
              onChange={(e) => setLocValue(e.target.value)}
              placeholder="https://... ou adresse"
              className="h-11"
            />
          </div>
          <div className="flex gap-2 pt-1">
            <Button variant="secondary" className="h-11" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button
              className="flex-1 h-11"
              onClick={submit}
              style={{ backgroundColor: CORAL }}
              disabled={saving || cooldown > 0}
            >
              {saving ? "Envoi..." : cooldown > 0 ? `Attendre ${cooldown}s` : "Proposer"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* -------------------- SessionsList / SessionCard -------------------- */

export function SessionsList({ matchId, meId }) {
  const [loading, setLoading] = useState(true);
  const [sessions, setSessions] = useState([]);

  const refresh = async () => {
    try {
      setLoading(true);
      const data = await listSessions(matchId);
      setSessions(data.sessions || []);
    } catch {
      setSessions([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (matchId) refresh();
  }, [matchId]);

  if (loading) {
    return (
      <Card className="mt-3">
        <CardContent className="p-3 space-y-2">
          <Skeleton className="h-5 w-1/4" />
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2 mt-3">
      {sessions.length === 0 && (
        <div className="text-sm text-muted-foreground">Aucune session pour ce match</div>
      )}
      {sessions.map((s) => (
        <SessionCard key={s.id} sess={s} meId={meId} onChanged={refresh} />
      ))}
    </div>
  );
}

export function SessionCard({ sess, meId, onChanged }) {
  const mine = meId === sess.proposedBy;

  const accept = async () => {
    try {
      await updateSession(sess.id, "confirmed");
      onChanged?.();
    } catch (e) {
      console.error(e);
    }
  };
  const refuse = async () => {
    try {
      await updateSession(sess.id, "cancelled");
      onChanged?.();
    } catch (e) {
      console.error(e);
    }
  };

  const canAccept = sess.status === "proposed" && !mine;
  const icsUrl = sess.status === "confirmed" ? downloadSessionIcs(sess.id) : null;
  const tz = "Asia/Jerusalem";
  const fmt = (d) => new Date(d).toLocaleString("fr-FR", { timeZone: tz, hour12: false });

  return (
    <Card>
      <CardContent className="p-3">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">
              {fmt(sess.startAt)} (
              {Math.round((new Date(sess.endAt) - new Date(sess.startAt)) / 60000)} min)
            </div>
            <div className="text-xs text-muted-foreground">
              {sess.locationType === "online" ? "Visio" : "En personne"} • {sess.locationValue}
            </div>
          </div>
          <Badge>{sess.status}</Badge>
        </div>
        <div className="flex gap-2 mt-2">
          {canAccept && (
            <>
              <Button className="h-10" style={{ backgroundColor: CORAL }} onClick={accept}>
                Accepter
              </Button>
              <Button className="h-10" variant="secondary" onClick={refuse}>
                Refuser
              </Button>
            </>
          )}
          {icsUrl && (
            <>
              <a className="text-sm px-3 py-2 rounded-md border hover:bg-muted" href={icsUrl}>
                Add to Calendar (.ics)
              </a>
              <a
                className="text-sm px-3 py-2 rounded-md border hover:bg-muted"
                target="_blank"
                rel="noreferrer"
                href={buildGoogleCalendarUrl(sess)}
              >
                Add to Google Calendar
              </a>
            </>
          )}
        </div>
        <RatingPrompt sess={sess} meId={meId} />
      </CardContent>
    </Card>
  );
}

function buildGoogleCalendarUrl(sess) {
  const start = new Date(sess.startAt).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z/, "Z");
  const end = new Date(sess.endAt).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z/, "Z");
  const params = new URLSearchParams({
    action: "TEMPLATE",
    text: "SkillSwap Session",
    dates: `${start}/${end}`,
    details: "Session SkillSwap",
    location: sess.locationValue || "",
  });
  return `https://calendar.google.com/calendar/render?${params.toString()}`;
}

/* -------------------- Rating (dialog) -------------------- */

function RatingPrompt({ sess }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (sess.status !== "confirmed") return;
    const end = new Date(sess.endAt).getTime();
    const show = Date.now() > end + 60 * 60 * 1000; // +1h
    if (show) setOpen(true);
  }, [sess]);
  if (!open) return null;
  return <RatingDialog open={open} onOpenChange={setOpen} sessionId={sess.id} />;
}

export function RatingDialog({ open, onOpenChange, sessionId }) {
  const { toast } = useToast();
  const [stars, setStars] = useState(5);
  const [comment, setComment] = useState("");
  const [posting, setPosting] = useState(false);
  const [already, setAlready] = useState(false);

  useEffect(() => {
    if (!open) return;
    (async () => {
      try {
        const r = await getMyRatingForSession(sessionId);
        // l'API peut renvoyer null/404 si non implémenté, ou un objet
        if (r?.rated || r?.rating) setAlready(true);
      } catch {
        // ignore
      }
    })();
  }, [open, sessionId]);

  const submit = async () => {
    if (already) {
      onOpenChange(false);
      return;
    }
    if (!stars || stars < 1 || stars > 5) {
      toast({ title: "Note 1–5" });
      return;
    }
    if (comment.length > 300) {
      toast({ title: "Commentaire trop long (≤300)" });
      return;
    }
    setPosting(true);
    try {
      await createRating({ sessionId, stars, comment });
      toast({ title: "Merci pour votre note" });
      onOpenChange(false);
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Impossible d'envoyer la note";
      toast({ title: "Erreur", description: msg });
    } finally {
      setPosting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Noter cette session</DialogTitle>
        </DialogHeader>
        {already ? (
          <div className="text-sm text-muted-foreground">Vous avez déjà noté cette session.</div>
        ) : (
          <div className="space-y-3">
            <div className="flex gap-1">
              {[1, 2, 3, 4, 5].map((i) => (
                <button
                  key={i}
                  onClick={() => setStars(i)}
                  className={(i <= stars ? "text-yellow-500" : "text-muted-foreground") + " text-2xl"}
                  aria-label={`Donner ${i} étoile(s)`}
                >
                  ★
                </button>
              ))}
            </div>
            <Input
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Commentaire (optionnel, ≤300)"
            />
            <div className="flex gap-2">
              <Button variant="secondary" onClick={() => onOpenChange(false)} className="h-11">
                Plus tard
              </Button>
              <Button onClick={submit} disabled={posting} className="h-11" style={{ backgroundColor: CORAL }}>
                {posting ? "Envoi..." : "Envoyer"}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
