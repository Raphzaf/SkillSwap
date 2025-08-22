import React, { useState } from "react";
import { Input } from "../../components/ui/input";
import { Button } from "../../components/ui/button";

export default function SkillsInput({ label, value, onChange, placeholder }) {
  const [draft, setDraft] = useState("");

  const skills = (value || "").split(",").map(s => s.trim()).filter(Boolean);

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
        <Input value={draft} onChange={e=>setDraft(e.target.value)} placeholder={placeholder || "Ex: React"} />
        <Button type="button" onClick={add}>Ajouter</Button>
      </div>
      <div className="flex flex-wrap gap-2 pt-1">
        {skills.map((s) => (
          <span key={s} className="px-2 py-1 text-xs rounded-full border">
            {s}{" "}
            <button onClick={()=>remove(s)} className="text-muted-foreground hover:underline">×</button>
          </span>
        ))}
      </div>
    </div>
  );
}
