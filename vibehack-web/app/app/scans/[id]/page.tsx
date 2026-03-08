"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";

import {
  appendScanEvent,
  buildScanEventsStreamUrl,
  getScan,
  listScanEvents,
  type ScanEventRecord,
  type ScanRecord,
} from "@/lib/api";
import { createClient } from "@/lib/supabase/client";

const supabase = createClient();

type StreamState = "idle" | "connecting" | "connected" | "reconnecting" | "disconnected";

function eventIdValue(event: ScanEventRecord): number {
  if (typeof event.id === "number") {
    return event.id;
  }
  if (typeof event.id === "string") {
    const parsed = Number.parseInt(event.id, 10);
    return Number.isNaN(parsed) ? 0 : parsed;
  }
  return 0;
}

export default function ScanDetailPage() {
  const params = useParams<{ id: string | string[] }>();
  const scanId = Array.isArray(params.id) ? params.id[0] : params.id;

  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [events, setEvents] = useState<ScanEventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<StreamState>("idle");
  const [streamError, setStreamError] = useState<string | null>(null);

  const [eventType, setEventType] = useState("progress");
  const [eventMessage, setEventMessage] = useState("Manual update from scans detail UI");
  const [appending, setAppending] = useState(false);
  const [appendError, setAppendError] = useState<string | null>(null);

  const mergeEvents = useCallback((incoming: ScanEventRecord[]) => {
    if (incoming.length === 0) {
      return;
    }

    setEvents((current) => {
      const byId = new Map<number, ScanEventRecord>();

      for (const item of current) {
        byId.set(eventIdValue(item), item);
      }
      for (const item of incoming) {
        byId.set(eventIdValue(item), item);
      }

      return Array.from(byId.values()).sort((a, b) => eventIdValue(a) - eventIdValue(b));
    });
  }, []);

  useEffect(() => {
    let mounted = true;

    supabase.auth.getSession().then(({ data, error: sessionError }) => {
      if (!mounted) {
        return;
      }

      if (sessionError) {
        setError(sessionError.message);
        setLoading(false);
        return;
      }

      setAccessToken(data.session?.access_token ?? null);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setAccessToken(session?.access_token ?? null);
    });

    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, []);

  useEffect(() => {
    if (!scanId) {
      setLoading(false);
      setError("Missing scan id in route.");
      return;
    }

    if (!accessToken) {
      setLoading(false);
      return;
    }

    const token = accessToken;
    const resolvedScanId = scanId;
    let cancelled = false;

    async function loadScanData() {
      setLoading(true);
      setError(null);

      try {
        const [scanData, scanEvents] = await Promise.all([
          getScan(token, resolvedScanId),
          listScanEvents(token, resolvedScanId),
        ]);

        if (cancelled) {
          return;
        }

        setScan(scanData);
        setEvents([]);
        mergeEvents(scanEvents);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load scan details.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadScanData();

    return () => {
      cancelled = true;
    };
  }, [accessToken, mergeEvents, scanId]);

  useEffect(() => {
    if (!scanId || !accessToken) {
      return;
    }

    const token = accessToken;
    const resolvedScanId = scanId;

    setStreamState("connecting");
    setStreamError(null);

    const source = new EventSource(buildScanEventsStreamUrl(resolvedScanId, token));

    const onConnected = () => {
      setStreamState("connected");
      setStreamError(null);
    };

    const onScanEvent = (event: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(event.data) as ScanEventRecord;
        mergeEvents([payload]);
      } catch {
        // Ignore malformed frames
      }
    };

    source.addEventListener("connected", onConnected as EventListener);
    source.addEventListener("scan_event", onScanEvent as EventListener);

    source.onerror = () => {
      setStreamState("reconnecting");
      setStreamError("Stream disconnected. Browser will retry automatically.");
    };

    return () => {
      source.close();
      setStreamState("disconnected");
    };
  }, [accessToken, mergeEvents, scanId]);

  const orderedEvents = useMemo(
    () => [...events].sort((a, b) => eventIdValue(a) - eventIdValue(b)),
    [events],
  );

  async function handleAppendEvent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppendError(null);

    if (!accessToken || !scanId) {
      setAppendError("Missing access token or scan id.");
      return;
    }

    setAppending(true);
    try {
      await appendScanEvent(accessToken, scanId, {
        eventType,
        data: {
          message: eventMessage,
          source: "vibehack-web",
          at: new Date().toISOString(),
        },
      });
      setEventMessage("Manual update from scans detail UI");
    } catch (err) {
      setAppendError(err instanceof Error ? err.message : "Failed to append event.");
    } finally {
      setAppending(false);
    }
  }

  const targetUrl =
    typeof scan?.target_url === "string"
      ? scan.target_url
      : typeof scan?.url === "string"
        ? scan.url
        : "Unknown target";

  const status = typeof scan?.status === "string" ? scan.status : "pending";

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <Link href="/app/scans" className="text-xs font-medium text-cyan-400 hover:text-cyan-300">
          ← Back to scans
        </Link>

        <h2 className="text-2xl font-semibold tracking-tight">Scan detail</h2>
        <p className="text-sm text-zinc-400">
          Live updates from <code>GET /api/scans/{scanId}/events/stream</code>
        </p>
      </div>

      {!accessToken ? (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
          Missing session access token. Please logout and login again.
        </p>
      ) : null}

      {error ? (
        <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </p>
      ) : null}

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        {loading ? (
          <p className="text-sm text-zinc-400">Loading scan details…</p>
        ) : (
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Scan id</dt>
              <dd className="font-mono text-zinc-200">{scanId}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Status</dt>
              <dd className="capitalize text-cyan-300">{status}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Target</dt>
              <dd className="truncate text-zinc-200">{targetUrl}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Stream</dt>
              <dd className="capitalize text-zinc-200">{streamState}</dd>
            </div>
          </dl>
        )}

        {streamError ? <p className="mt-3 text-xs text-amber-300">{streamError}</p> : null}
      </div>

      <form
        onSubmit={handleAppendEvent}
        className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-900 p-4"
      >
        <h3 className="text-sm font-semibold">Send test event</h3>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="space-y-1">
            <span className="text-xs font-medium uppercase tracking-wide text-zinc-400">Event type</span>
            <input
              type="text"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-cyan-500"
              required
            />
          </label>

          <label className="space-y-1 sm:col-span-2">
            <span className="text-xs font-medium uppercase tracking-wide text-zinc-400">Message</span>
            <input
              type="text"
              value={eventMessage}
              onChange={(e) => setEventMessage(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-cyan-500"
              required
            />
          </label>
        </div>

        {appendError ? <p className="text-xs text-rose-300">{appendError}</p> : null}

        <button
          type="submit"
          disabled={appending}
          className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-70"
        >
          {appending ? "Sending..." : "Send test event"}
        </button>
      </form>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900">
        <div className="border-b border-zinc-800 px-4 py-3">
          <h3 className="text-sm font-semibold">Live events</h3>
        </div>

        {orderedEvents.length === 0 ? (
          <p className="px-4 py-6 text-sm text-zinc-400">No events yet for this scan.</p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {orderedEvents.map((event, index) => {
              const createdAt =
                typeof event.created_at === "string"
                  ? new Date(event.created_at).toLocaleString()
                  : "—";
              const type = typeof event.event_type === "string" ? event.event_type : "event";
              const payload = event.data ?? {};

              return (
                <li key={`${eventIdValue(event)}-${index}`} className="space-y-2 px-4 py-3 text-sm">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="font-mono text-xs text-zinc-400">#{eventIdValue(event)}</span>
                    <span className="text-cyan-300">{type}</span>
                    <span className="text-xs text-zinc-500">{createdAt}</span>
                  </div>
                  <pre className="overflow-x-auto rounded bg-zinc-950 p-2 text-xs text-zinc-300">
                    {JSON.stringify(payload, null, 2)}
                  </pre>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
