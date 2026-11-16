import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage } from "../api/client";

/** Fetch data on mount and whenever `deps` change; `reload()` refetches. */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const seq = useRef(0);

  const reload = useCallback(async (silent = false) => {
    const id = ++seq.current;
    if (!silent) setLoading(true);
    try {
      const result = await fnRef.current();
      if (id === seq.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (id === seq.current) setError(errorMessage(err));
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setData };
}
