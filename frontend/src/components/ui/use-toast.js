import { useCallback } from "react";


export function useToast() {
  const toast = useCallback(({ title, description }) => {
    if (description) {
      alert(`${title}\n${description}`);
    } else {
      alert(title);
    }
  }, []);

  return { toast };
}
