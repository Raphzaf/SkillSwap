import React, { useEffect, useMemo, useState } from "react";
import { Card, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { Skeleton } from "../components/ui/skeleton";
import { Heart, X, Star, Sparkles, Info } from "lucide-react";
import { CORAL, nextProfile } from "../mock";
import { getCandidates, sendSwipe } from "../lib/api";

// Helper to normalize candidate data from API
const normalizeCandidate = (c) => ({
  id: c.id,
  name: c.name,
  age: c.age,
  bio: c.bio,
  photos: c.photos || [],
  skillsToTeach: c.skillsTeach || [],
  skillsToLearn: c.skillsLearn || [],
  distanceKm: c.distanceKm || 5,
  avgRating: c.avgRating || 0,
  ratingsCount: c.ratingsCount || 0,
  creditBalance: c.creditBalance || 100,
  matchScore: c.matchScore || 0,
  matchReasons: c.matchReasons || [],
  isMutualMatch: c.isMutualMatch || false,
});

export default function Swipe() {
  const [index, setIndex] = useState(0);
  const [outDir, setOutDir] = useState(null);
  const [showMatch, setShowMatch] = useState(false);
  const [deck, setDeck] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const d = await getCandidates(0, 10);
        if (!mounted) return;
        const items = (d.candidates || []).map(normalizeCandidate);
        setDeck(items);
        setCursor(Number(d.nextCursor || 10));
      } catch (e) {
        setDeck([nextProfile(0), nextProfile(1), nextProfile(2)]);
        setCursor(3);
      } finally { setLoading(false); }
    })();
    return () => { mounted = false; };
  }, []);

  const ensureMore = async () => {
    if (deck.length - index > 3) return;
    try {
      const d = await getCandidates(cursor, 10);
      const items = (d.candidates || []).map(normalizeCandidate);
      setDeck((prev) => [...prev, ...items]);
      setCursor(Number(d.nextCursor || (cursor + 10)));
    } catch {}
  };

  useEffect(() => { ensureMore(); }, [index]);

  const top = deck[index];
  const second = deck[index + 1] || null;
  const third = deck[index + 2] || null;

  const triggerSwipe = (dir) => {
    setOutDir(dir);
    setTimeout(() => {
      setIndex((i) => i + 1);
      setOutDir(null);
    }, 270);
  };

  const onPass = async () => {
    if (top?.id) try { await sendSwipe(top.id, "pass"); } catch {}
    triggerSwipe("left");
  };
  const onLike = async () => {
    if (top?.id) {
      try {
        const res = await sendSwipe(top.id, "like");
        if (res.matched) setShowMatch(true);
      } catch {}
    }
    triggerSwipe("right");
  };
  const onSuperLike = async () => {
    if (top?.id) {
      try {
        const res = await sendSwipe(top.id, "superlike");
        if (res.matched) setShowMatch(true);
      } catch {}
    }
    triggerSwipe("up");
  };

  const renderCard = (p, idx, z) => (
    <Card
      key={(p?.id || "mock") + idx}
      className={
        "absolute inset-0 shadow-xl rounded-xl overflow-hidden bg-card transition-transform duration-300" +
        (idx === 2 && outDir === "left"
          ? " -translate-x-[120%] -rotate-6"
          : idx === 2 && outDir === "right"
          ? " translate-x-[120%] rotate-6"
          : idx === 2 && outDir === "up"
          ? " -translate-y-[120%]"
          : "") +
        (idx === 1 ? " scale-[0.97] translate-y-2" : "") +
        (idx === 0 ? " scale-[0.94] translate-y-4" : "")
      }
      style={{ zIndex: z }}
    >
      <CardContent className="p-0 h-full">
        <div className="h-3/5 w-full bg-muted overflow-hidden">
          {p ? (<img src={(p?.photos?.[0])} alt={p?.name || "person"} className="w-full h-full object-cover" />) : <Skeleton className="w-full h-full" />}
        </div>
        <div className="p-4 space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{p?.name}{p?.age ? `, ${p.age}` : ""}</h3>
              <div className="flex items-center gap-2">
                <p className="text-sm text-muted-foreground">{p?.distanceKm ?? 1} km away</p>
                {p?.avgRating > 0 && (
                  <div className="flex items-center gap-1 text-xs text-amber-600">
                    <Star className="h-3 w-3 fill-current" />
                    <span>{p.avgRating.toFixed(1)}</span>
                    <span className="text-muted-foreground">({p.ratingsCount})</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex gap-1 flex-wrap justify-end max-w-[50%]">
              {(p?.skillsToTeach || []).slice(0,2).map((s) => (
                <Badge key={s} className="bg-[var(--accent)]/20 text-[var(--foreground)]" style={{ borderColor: CORAL, color: CORAL }}>{s}</Badge>
              ))}
            </div>
          </div>
          
          {/* Match Score */}
          {p?.isMutualMatch && (
            <div className="flex items-center gap-2 p-2 bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-950 dark:to-pink-950 rounded-lg">
              <Sparkles className="h-4 w-4 text-purple-600" />
              <span className="text-sm font-semibold text-purple-600">Perfect Match!</span>
            </div>
          )}
          {p?.matchScore > 0 && !p?.isMutualMatch && (
            <div className="flex items-center justify-between p-2 bg-muted/50 rounded-lg">
              <div className="flex items-center gap-2">
                <div className="text-sm font-semibold">Match Score</div>
                <div className="text-xl font-bold text-green-600">{p.matchScore}%</div>
              </div>
              {p?.matchReasons?.length > 0 && (
                <Button variant="ghost" size="sm" className="h-6 px-2">
                  <Info className="h-3 w-3" />
                </Button>
              )}
            </div>
          )}
          
          {/* Match Reasons */}
          {p?.matchReasons?.length > 0 && (
            <div className="text-xs text-muted-foreground space-y-1">
              {p.matchReasons.slice(0, 2).map((reason, idx) => (
                <div key={idx} className="flex items-start gap-1">
                  <span>•</span>
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          )}
          
          <p className="text-sm leading-relaxed line-clamp-2">{p?.bio}</p>
          <div className="text-xs text-muted-foreground">
            Wants to learn: {(p?.skillsToLearn || []).slice(0, 3).join(", ")}
            {(p?.skillsToLearn || []).length > 3 && "..."}
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="w-full max-w-md mx-auto p-4">
      <div className="relative h-[520px]">
        {loading ? (
          <div className="absolute inset-0 p-4 space-y-3">
            <Skeleton className="h-2/3 w-full" />
            <Skeleton className="h-5 w-1/2" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ) : (
          [third, second, top].map((p, idx) => renderCard(p, idx, 10 + idx))
        )}
      </div>

      <div className="mt-4 flex items-center justify-between gap-3">
        <Button variant="secondary" className="flex-1 h-12" onClick={onPass}>
          <X className="mr-2" /> Pass
        </Button>
        <Button className="flex-1 h-12" style={{ backgroundColor: CORAL }} onClick={onSuperLike}>
          <Star className="mr-2" /> Super Like
        </Button>
        <Button variant="secondary" className="flex-1 h-12" onClick={onLike}>
          <Heart className="mr-2" /> Like
        </Button>
      </div>

      <Dialog open={showMatch} onOpenChange={setShowMatch}>
        <DialogContent className="sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle style={{ color: CORAL }}>It's a match!</DialogTitle>
            <DialogDescription>
              You both want to swap skills. Say hi and set up your first session.
            </DialogDescription>
          </DialogHeader>
          <div className="flex gap-3">
            <Button className="flex-1" onClick={() => setShowMatch(false)} style={{ backgroundColor: CORAL }}>Open Chat</Button>
            <Button className="flex-1" variant="secondary" onClick={() => setShowMatch(false)}>Keep Swiping</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}