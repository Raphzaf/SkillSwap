import React from "react";
import { Input } from "../../components/ui/input";
import { Button } from "../../components/ui/button";

export default function PhotosInput({ value, onChange, max = 6 }) {
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
