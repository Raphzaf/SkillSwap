import React from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Query Client global: cache fiable, peu de retries pour éviter le spam en dev
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,            // 20s de fraicheur
      retry: 1,                     // un seul retry en cas d’échec
      refetchOnWindowFocus: false,  // pas de refetch quand on revient sur l’onglet
    },
    mutations: {
      retry: 0,                     // pas de retry implicite sur les mutations (envoyer un message, etc.)
    },
  },
});

// Assure l’existence du conteneur racine
let rootEl = document.getElementById("root");
if (!rootEl) {
  rootEl = document.createElement("div");
  rootEl.id = "root";
  document.body.appendChild(rootEl);
}

const root = createRoot(rootEl);

root.render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>
);
