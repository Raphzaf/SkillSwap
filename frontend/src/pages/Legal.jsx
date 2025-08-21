import React, { useState } from "react";
import { Button } from "../components/ui/button";
import { Card, CardContent } from "../components/ui/card";
import { useToast } from "../components/ui/use-toast";
import { exportMyData, deleteMyAccount } from "../lib/api";

function downloadBlob(blob, filename) {
  // Edge (legacy) support
  if (window.navigator && window.navigator.msSaveOrOpenBlob) {
    window.navigator.msSaveOrOpenBlob(blob, filename);
    return;
  }
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  // Safari a besoin d’un léger délai avant revoke
  setTimeout(() => {
    URL.revokeObjectURL(link.href);
    link.remove();
  }, 800);
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, filename);
}

export default function Legal() {
  const { toast } = useToast();
  const [busyExport, setBusyExport] = useState(false);
  const [busyDelete, setBusyDelete] = useState(false);

  const onExport = async () => {
    setBusyExport(true);
    try {
      // Tente d’abord un export "blob" si l’API le supporte (optionnel selon ton wrapper)
      let data = await exportMyData({ as: "blob" }).catch(() => null);
      if (data instanceof Blob) {
        downloadBlob(data, `skillswap_export_${Date.now()}.json`);
      } else {
        // Fallback: l’API renvoie du JSON (objet)
        data = await exportMyData();
        downloadJson(data, `skillswap_export_${Date.now()}.json`);
      }
      toast({ title: "Export prêt", description: "Le fichier JSON a été téléchargé." });
    } catch (e) {
      toast({ title: "Export impossible", description: e?.message || "Erreur réseau" });
    } finally {
      setBusyExport(false);
    }
  };

  const onDelete = async () => {
    if (!window.confirm("Confirmer la suppression de votre compte ? Cette action est irréversible.")) return;
    if (!window.confirm("Dernière confirmation : vos messages seront anonymisés et vos sessions futures annulées.")) return;
    setBusyDelete(true);
    try {
      await deleteMyAccount();
      toast({ title: "Compte supprimé", description: "Vous allez être déconnecté." });
      // Nettoyage stockage + petit délai pour laisser le toast s’afficher
      localStorage.removeItem("ss_token");
      localStorage.removeItem("ss_refresh");
      localStorage.removeItem("ss_me_id");
      sessionStorage.clear();
      setTimeout(() => (window.location.href = "/"), 900);
    } catch (e) {
      toast({ title: "Suppression impossible", description: e?.message || "Erreur réseau" });
    } finally {
      setBusyDelete(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-4">
      <h1 className="text-2xl font-semibold">Confidentialité & RGPD (MVP)</h1>
      <Card>
        <CardContent className="space-y-3 p-4">
          <p className="text-sm text-muted-foreground">
            Vous pouvez exporter vos données au format JSON et demander la suppression de votre compte.
            La suppression anonymise vos messages (<code>[deleted]</code>) et annule vos sessions futures.
          </p>
          <p className="text-xs text-muted-foreground">
            Astuce : l’export peut prendre quelques secondes selon la taille de vos données.
          </p>
          <div className="flex gap-2">
            <Button aria-busy={busyExport} disabled={busyExport || busyDelete} onClick={onExport}>
              {busyExport ? "Export en cours…" : "Exporter mes données (JSON)"}
            </Button>
            <Button
              aria-busy={busyDelete}
              disabled={busyExport || busyDelete}
              variant="destructive"
              onClick={onDelete}
            >
              {busyDelete ? "Suppression…" : "Supprimer mon compte"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
