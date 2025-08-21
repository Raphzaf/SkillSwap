import React from "react";
import RatingStars from "../RatingStars";

export default function RatingsSummary({ user }) {
  const avg = Number(user?.avgRating || 0);
  const count = Number(user?.ratingsCount || 0);
  return (
    <div className="flex items-center gap-3">
      <RatingStars value={avg} size="text-xl" showValue />
      <span className="text-sm text-muted-foreground">
        {count > 0 ? `${count} avis` : `Aucun avis pour le moment`}
      </span>
    </div>
  );
}
