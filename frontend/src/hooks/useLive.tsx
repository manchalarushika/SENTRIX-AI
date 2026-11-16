import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { wsUrl } from "../api/client";

export interface LiveMessage {
  type: string;
  ts?: string;
  data: Record<string, any>;
}

type Listener = (m: LiveMessage) => void;

interface LiveCtx {
  connected: boolean;
  feed: LiveMessage[];
  subscribe: (fn: Listener) => () => void;
}

const Ctx = createContext<LiveCtx>({ connected: false, feed: [], subscribe: () => () => undefined });

/** Maintains one WebSocket to /ws/live with automatic reconnect. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [feed, setFeed] = useState<LiveMessage[]>([]);
  const listeners = useRef(new Set<Listener>());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let ping: ReturnType<typeof setInterval> | undefined;
    let closed = false;

    const open = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => {
        setConnected(true);
        ping = setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 25000);
      };
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data) as LiveMessage;
          if (msg.type === "pong" || msg.type === "connected") return;
          setFeed((f) => [msg, ...f].slice(0, 100));
          listeners.current.forEach((l) => l(msg));
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        clearInterval(ping);
        if (!closed) retry = setTimeout(open, 3000);
      };
      ws.onerror = () => ws?.close();
    };
    open();
    return () => {
      closed = true;
      clearTimeout(retry);
      clearInterval(ping);
      ws?.close();
    };
  }, []);

  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  return <Ctx.Provider value={{ connected, feed, subscribe }}>{children}</Ctx.Provider>;
}

export const useLive = () => useContext(Ctx);

/** Run `fn` (debounced) whenever a live message of one of `types` arrives. */
export function useLiveRefresh(types: string[], fn: () => void, delay = 800) {
  const { subscribe } = useLive();
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const key = types.join(",");
  useEffect(() => {
    let t: ReturnType<typeof setTimeout> | undefined;
    const unsub = subscribe((m) => {
      if (key.split(",").includes(m.type)) {
        clearTimeout(t);
        t = setTimeout(() => fnRef.current(), delay);
      }
    });
    return () => {
      clearTimeout(t);
      unsub();
    };
  }, [key, delay, subscribe]);
}
