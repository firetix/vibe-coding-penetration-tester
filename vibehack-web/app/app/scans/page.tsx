"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import {
  createScan,
  listScans,
  type CreateScanInput,
  type ScanRecord,
} from "@/lib/api";
import { createClient } from "@/lib/supabase/client";

const supabase = createClient();

export default function ScansPage() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState("quick");
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const loadScans = useCallback(async (token: string) => {
    setLoading(true);
    setError(null);

    try {
      const items = await listScans(token);
      setScans(items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load scans.");
    } finally {
      setLoading(false);
    }
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
    if (!accessToken) {
      setLoading(false);
      return;
    }

    void loadScans(accessToken);
  }, [accessToken, loadScans]);

  const sortedScans = useMemo(() => {
    return [...scans].sort((a, b) => {
      const first = Date.parse(String(a.created_at ?? ""));
      const second = Date.parse(String(b.created_at ?? ""));

      if (Number.isNaN(first) || Number.isNaN(second)) {
        return 0;
      }

      return second - first;
    });
  }, [scans]);

  async function handleCreateScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSuccessMessage(null);

    if (!accessToken) {
      setError("No active access token found. Please login again.");
      return;
    }

    const payload: CreateScanInput = {
      targetUrl,
      scanMode,
    };

    setCreating(true);

    try {
      await createScan(accessToken, payload);
      setSuccessMessage("Scan submitted successfully.");
      setTargetUrl("");
      await loadScans(accessToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Scans</h2>
        <p className="text-sm text-zinc-400">
          Create a new scan via <code>POST /api/scans</code> and list existing scans via
          <code> GET /api/scans</code>.
        </p>
      </div>

      <form
        onSubmit={handleCreateScan}
        className="space-y-4 rounded-lg border border-zinc-800 bg-zinc-900 p-4"
      >
        <div className="space-y-1">
          <label htmlFor="target_url" className="text-xs font-medium uppercase tracking-wide text-zinc-400">
            Target URL
          </label>
          <input
            id="target_url"
            type="url"
            required
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://target.example"
            className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-cyan-500"
          />
        </div>

        <div className="space-y-1">
          <label htmlFor="scan_mode" className="text-xs font-medium uppercase tracking-wide text-zinc-400">
            Scan mode
          </label>
          <select
            id="scan_mode"
            value={scanMode}
            onChange={(event) => setScanMode(event.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-cyan-500"
          >
            <option value="quick">Quick</option>
            <option value="deep">Deep</option>
          </select>
        </div>

        <button
          type="submit"
          disabled={creating}
          className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-70"
        >
          {creating ? "Creating scan..." : "Create scan"}
        </button>
      </form>

      {successMessage ? (
        <p className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          {successMessage}
        </p>
      ) : null}

      {error ? (
        <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </p>
      ) : null}

      {!accessToken ? (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
          Missing session access token. Please logout and login again.
        </p>
      ) : null}

      <div className="rounded-lg border border-zinc-800 bg-zinc-900">
        <div className="border-b border-zinc-800 px-4 py-3">
          <h3 className="text-sm font-semibold">Recent scans</h3>
        </div>

        {loading ? (
          <p className="px-4 py-6 text-sm text-zinc-400">Loading scans…</p>
        ) : sortedScans.length === 0 ? (
          <p className="px-4 py-6 text-sm text-zinc-400">No scans yet. Create your first scan above.</p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {sortedScans.map((scan, index) => {
              const scanId =
                typeof scan.id === "string" || typeof scan.id === "number"
                  ? String(scan.id)
                  : typeof scan.scan_id === "string" || typeof scan.scan_id === "number"
                    ? String(scan.scan_id)
                    : `scan-${index + 1}`;

              const target =
                typeof scan.target_url === "string"
                  ? scan.target_url
                  : typeof scan.url === "string"
                    ? scan.url
                    : "Unknown target";

              const status =
                typeof scan.status === "string" ? scan.status : "queued";

              const createdAt =
                typeof scan.created_at === "string"
                  ? new Date(scan.created_at).toLocaleString()
                  : "—";

              return (
                <li key={`${scanId}-${index}`} className="grid gap-1 px-4 py-3 text-sm sm:grid-cols-4 sm:gap-2">
                  <span className="font-mono text-xs text-zinc-400">{scanId}</span>
                  <span className="truncate sm:col-span-2">{target}</span>
                  <span className="capitalize text-cyan-300">{status}</span>
                  <span className="text-xs text-zinc-400 sm:col-span-4">Created: {createdAt}</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
