import React from "react";

export default function RatingStars({ value = 0, size = "text-base", showValue = false }) {
  const full = Math.floor(value || 0);
  const hasHalf = value - full >= 0.5;
  const arr = [0,1,2,3,4].map(i => {
    if (i < full) return "★";
    if (i === full && hasHalf) return "☆"; // simple demi (tu peux raffiner en SVG)
    return "☆";
  });
  return (
    <div className={`inline-flex items-center gap-1 ${size}`} aria-label={`Note ${value}/5`}>
      <div className="leading-none">{arr.join("")}</div>
      {showValue && <span className="text-muted-foreground ml-1">{Number(value || 0).toFixed(1)}</span>}
    </div>
  );
}
