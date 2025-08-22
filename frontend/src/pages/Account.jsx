import React, { useEffect, useState } from "react";
import { Card, CardContent } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Button } from "../components/ui/button";
import { Label } from "../components/ui/label";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "../components/ui/select";
import { Separator } from "../components/ui/separator";
import { useToast } from "../components/ui/use-toast";
import { getMe, updateMe, updateSettings } from "../lib/api";

/* -------------------------- Petits sous-composants -------------------------- */

function Field({ label, children, help }) {
  return (
    <div className="space-y-1">
      <Label className="text-sm">{label}</Label>
      {children}
      {help && <div className="text-xs text-muted-foreground">{help}</div>}
    </div>
  );
}

function SkillsInput({ label, value, onChange, placeholder }) {
  const skills = (value || "").split(",").map(s => s.trim()).filter(Boolean);
  const [draft, setDraft] = useState("");

  const add = () => {
    const v = draft.trim();
    if (!v) return;
    const set = new Set(skills);
    set.add(v);
    onChange([...set].join(", "));
    setDraft("");
  };

  const remove = (s) => {
    onChange(skills.filter(x => x.toLowerCase() !== s.toLowerCase()).join(", "));
  };

  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">{label}</div>
      <div className="flex gap-2">
        <Input value={draft} onChange={(e)=>setDraft(e.target.value)} placeholder={placeholder || "Ex: React"} />
        <Button type="button" onClick={add}>Ajouter</Button>
      </div>
      <div className="flex flex-wrap gap-2 pt-1">
        {skills.map((s) => (
          <span key={s} className="px-2 py-1 text-xs rounded-full border">
            {s}{" "}
            <button onClick={()=>remove(s)} className="text-muted-foreground hover:underline" aria-label={`Supprimer ${s}`}>×</button>
          </span>
        ))}
      </div>
    </div>
  );
}

function PhotosInput({ value, onChange, max = 6 }) {
  const urls = (value || "").split("\n").map(x=>x.trim()).filter(Boolean).slice(0, max);
  const setUrls = (arr) => onChange(arr.join("\n"));
  const add = () => setUrls([...urls, "https://"]);
  const remove = (i) => setUrls(urls.filter((_,idx)=>idx!==i));
  const update = (i, v) => setUrls(urls.map((u,idx)=>idx===i?v:u));

  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">Photos (URLs https)</div>
      {urls.map((u, i)=>(
        <div key={i} className="grid grid-cols-[1fr_auto] gap-2 items-center">
          <Input value={u} onChange={(e)=>update(i, e.target.value)} placeholder="https://…" />
          <Button type="button" variant="secondary" onClick={()=>remove(i)}>Supprimer</Button>
          <div className="col-span-2">
            {/^https:\/\//.test(u) ? (
              <img src={u} alt="" className="w-32 h-32 object-cover rounded-md border" onError={(e)=>{e.currentTarget.style.opacity=0.4;}} />
            ) : <div className="text-xs text-muted-foreground">Doit commencer par https://</div>}
          </div>
        </div>
      ))}
      {urls.length < max && <Button type="button" onClick={add}>Ajouter une photo</Button>}
      <div className="text-xs text-muted-foreground">Maximum {max} photos</div>
    </div>
  );
}

/* --------------------------------- Page ------------------------------------ */

export default function Account() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);

  // --- user
  const [name, setName] = useState("");
  const [age, setAge] = useState("");
  const [bio, setBio] = useState("");
  const [skillsTeach, setSkillsTeach] = useState("");
  const [skillsLearn, setSkillsLearn] = useState("");
  const [photos, setPhotos] = useState("");
  const [locationCity, setLocationCity] = useState("");

  // --- settings
  const [distanceKm, setDistanceKm] = useState(25);
  const [ageMin, setAgeMin] = useState(18);
  const [ageMax, setAgeMax] = useState(99);
  const [visibility, setVisibility] = useState("public");
  const [timezone, setTimezone] = useState("");
  const [notifications, setNotifications] = useState(true);
  const [lon, setLon] = useState("");
  const [lat, setLat] = useState("");

  const [savingProfile, setSavingProfile] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const data = await getMe();
        const u = data?.user || {};
        const s = data?.settings || {};

        setName(u.name || "");
        setAge(u.age || "");
        setBio(u.bio || "");
        setSkillsTeach((u.skillsTeach || []).join(", "));
        setSkillsLearn((u.skillsLearn || []).join(", "));
        setPhotos((u.photos || []).join("\n"));
        setLocationCity(u.locationCity || "");

        setDistanceKm(s.distanceKm ?? 25);
        const rng = s.ageRange || [18, 99];
        setAgeMin(rng[0]);
        setAgeMax(rng[1]);
        setVisibility(s.visibility || "public");
        setTimezone(s.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
        setNotifications(Boolean(s.notifications));
        if (s.location?.coordinates) {
          setLon(s.location.coordinates[0]);
          setLat(s.location.coordinates[1]);
        }
      } catch (e) {
        console.error(e);
        toast({ title: "Erreur", description: "Impossible de charger votre profil" });
      } finally {
        setLoading(false);
      }
    })();
  }, [toast]);

  const geolocate = () => {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLon(pos.coords.longitude.toFixed(5));
        setLat(pos.coords.latitude.toFixed(5));
      },
      () => {/* ignore */},
      { enableHighAccuracy: true, timeout: 6000 }
    );
  };

  const saveProfile = async () => {
    const ageNum = age ? Number(age) : undefined;
    if (age && (Number.isNaN(ageNum) || ageNum < 13 || ageNum > 120)) {
      toast({ title: "Âge invalide", description: "13–120" });
      return;
    }

    const photosList = (photos || "")
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean);

    if (photosList.length > 6) {
      toast({ title: "Trop de photos", description: "Max 6" });
      return;
    }
    for (const url of photosList) {
      if (!/^https:\/\//.test(url)) {
        toast({ title: "URL photo invalide", description: url });
        return;
      }
    }

    const payload = {
      name: name?.trim() || undefined,
      age: age ? ageNum : undefined,
      bio: bio?.trim() || undefined,
      skillsTeach: (skillsTeach || "")
        .split(",").map((x) => x.trim()).filter(Boolean),
      skillsLearn: (skillsLearn || "")
        .split(",").map((x) => x.trim()).filter(Boolean),
      photos: photosList,
      locationCity: locationCity?.trim() || undefined,
    };

    setSavingProfile(true);
    try {
      await updateMe(payload);
      toast({ title: "Profil enregistré" });
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Erreur serveur";
      toast({ title: "Erreur", description: String(msg) });
    } finally {
      setSavingProfile(false);
    }
  };

  const saveSettings = async () => {
    const dKm = Number(distanceKm);
    const minA = Number(ageMin);
    const maxA = Number(ageMax);
    if (Number.isNaN(dKm) || dKm < 1 || dKm > 200) {
      toast({ title: "Distance invalide", description: "1–200 km" });
      return;
    }
    if (Number.isNaN(minA) || Number.isNaN(maxA) || minA < 13 || maxA > 120 || minA > maxA) {
      toast({ title: "Plage d’âge invalide" });
      return;
    }

    let location = undefined;
    const lonNum = Number(lon), latNum = Number(lat);
    if (!Number.isNaN(lonNum) && !Number.isNaN(latNum)) {
      location = { type: "Point", coordinates: [lonNum, latNum] };
    }

    const payload = {
      distanceKm: dKm,
      ageRange: [minA, maxA],
      visibility,
      timezone: timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
      notifications,
      location,
    };

    setSavingSettings(true);
    try {
      await updateSettings(payload);
      toast({ title: "Préférences enregistrées" });
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Erreur serveur";
      toast({ title: "Erreur", description: String(msg) });
    } finally {
      setSavingSettings(false);
    }
  };

  if (loading) {
    return <div className="text-sm text-muted-foreground">Chargement…</div>;
  }

  const tzOptions = ["Europe/Paris","UTC","Europe/Brussels","America/New_York","Asia/Jerusalem"];

  return (
    <div className="grid md:grid-cols-2 gap-6">
      {/* Profil */}
      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="text-lg font-semibold">Mon profil</h2>
          <Field label="Nom">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Prénom" />
          </Field>
          <Field label="Âge">
            <Input type="number" min={13} max={120} value={age} onChange={(e) => setAge(e.target.value)} />
          </Field>
          <Field label="Bio" help="Max 500 caractères">
            <Input value={bio} onChange={(e) => setBio(e.target.value)} placeholder="Quelques mots sur vous" />
          </Field>

          <SkillsInput label="Compétences à enseigner" value={skillsTeach} onChange={setSkillsTeach} placeholder="React, Figma" />
          <SkillsInput label="Compétences à apprendre" value={skillsLearn} onChange={setSkillsLearn} placeholder="Node, Anglais" />

          <PhotosInput value={photos} onChange={setPhotos} />

          <Field label="Ville (libre)">
            <Input value={locationCity} onChange={(e) => setLocationCity(e.target.value)} placeholder="Paris…" />
          </Field>

          <div className="pt-2">
            <Button onClick={saveProfile} disabled={savingProfile}>
              {savingProfile ? "Enregistrement..." : "Enregistrer le profil"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Préférences */}
      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="text-lg font-semibold">Mes préférences</h2>
          <Field label="Distance max (km)">
            <Input type="number" min={1} max={200} value={distanceKm} onChange={(e) => setDistanceKm(e.target.value)} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Âge min">
              <Input type="number" min={13} max={120} value={ageMin} onChange={(e) => setAgeMin(e.target.value)} />
            </Field>
            <Field label="Âge max">
              <Input type="number" min={13} max={120} value={ageMax} onChange={(e) => setAgeMax(e.target.value)} />
            </Field>
          </div>
          <Field label="Visibilité">
            <Select value={visibility} onValueChange={setVisibility}>
              <SelectTrigger><SelectValue placeholder="public/private" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="public">Public</SelectItem>
                <SelectItem value="private">Privé</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="Fuseau horaire">
            <select className="border rounded-md px-2 h-10 w-full" value={timezone} onChange={(e)=>setTimezone(e.target.value)}>
              {[timezone, ...tzOptions.filter(t=>t!==timezone)].map(tz => <option key={tz} value={tz}>{tz}</option>)}
            </select>
          </Field>
          <Field label="Notifications">
            <div className="flex items-center gap-2">
              <input id="notif" type="checkbox" checked={notifications} onChange={(e) => setNotifications(e.target.checked)} />
              <Label htmlFor="notif">Activer les notifications</Label>
            </div>
          </Field>
          <Separator />
          <h3 className="font-medium">Position (optionnel)</h3>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Longitude (−180 → 180)">
              <Input value={lon} onChange={(e) => setLon(e.target.value)} placeholder="2.3522" />
            </Field>
            <Field label="Latitude (−90 → 90)">
              <Input value={lat} onChange={(e) => setLat(e.target.value)} placeholder="48.8566" />
            </Field>
          </div>
          <Button type="button" variant="secondary" onClick={geolocate}>Me localiser</Button>

          <div className="pt-2">
            <Button onClick={saveSettings} disabled={savingSettings}>
              {savingSettings ? "Enregistrement..." : "Enregistrer les préférences"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
