import { getApiBaseUrl } from "@/lib/env";

export type ScanRecord = {
  id?: string | number;
  scan_id?: string | number;
  status?: string;
  url?: string;
  target_url?: string;
  created_at?: string;
  [key: string]: unknown;
};

export type ScanEventRecord = {
  id?: string | number;
  scan_id?: string | number;
  event_type?: string;
  data?: Record<string, unknown>;
  created_at?: string;
  [key: string]: unknown;
};

export type CreateScanInput = {
  targetUrl: string;
  scanMode?: string;
};

export type AppendScanEventInput = {
  eventType: string;
  data?: Record<string, unknown>;
};

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null;
}

function buildUrl(path: string) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${getApiBaseUrl()}${normalizedPath}`;
}

function parseJson(raw: string) {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

function extractError(payload: unknown) {
  if (!isRecord(payload)) {
    return null;
  }

  const possibleFields = ["error", "message", "detail"] as const;
  for (const field of possibleFields) {
    const value = payload[field];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }

  return null;
}

function collectScanArray(value: unknown): ScanRecord[] {
  if (Array.isArray(value)) {
    return value.filter(isRecord) as ScanRecord[];
  }

  return [];
}

function normalizeScans(payload: unknown): ScanRecord[] {
  if (Array.isArray(payload)) {
    return payload.filter(isRecord) as ScanRecord[];
  }

  if (!isRecord(payload)) {
    return [];
  }

  const container = isRecord(payload.data) ? payload.data : payload;
  const direct = collectScanArray(container.scans ?? container.items ?? container.results);
  if (direct.length > 0) {
    return direct;
  }

  const active = collectScanArray(container.active);
  const completed = collectScanArray(container.completed);

  if (active.length > 0 || completed.length > 0) {
    return [...active, ...completed];
  }

  return [];
}

function normalizeScan(payload: unknown): ScanRecord | null {
  if (!isRecord(payload)) {
    return null;
  }

  const container = isRecord(payload.data) ? payload.data : payload;
  if (isRecord(container.scan)) {
    return container.scan as ScanRecord;
  }

  if (typeof container.id === "string" || typeof container.id === "number") {
    return container as ScanRecord;
  }

  return null;
}

function normalizeEvents(payload: unknown): ScanEventRecord[] {
  if (Array.isArray(payload)) {
    return payload.filter(isRecord) as ScanEventRecord[];
  }

  if (!isRecord(payload)) {
    return [];
  }

  const container = isRecord(payload.data) ? payload.data : payload;
  if (Array.isArray(container.events)) {
    return container.events.filter(isRecord) as ScanEventRecord[];
  }

  return [];
}

async function request<T>(
  path: string,
  accessToken: string,
  init: RequestInit,
): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  headers.set("Accept", "application/json");

  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  const response = await fetch(buildUrl(path), {
    ...init,
    headers,
    cache: "no-store",
  });

  const payload = parseJson(await response.text());

  if (!response.ok) {
    const message = extractError(payload) ?? `Request failed (${response.status})`;
    throw new Error(message);
  }

  return payload as T;
}

export function buildScanEventsStreamUrl(scanId: string, accessToken: string, lastEventId?: number) {
  const url = new URL(buildUrl(`/api/scans/${encodeURIComponent(scanId)}/events/stream`));
  url.searchParams.set("access_token", accessToken);

  if (typeof lastEventId === "number" && Number.isFinite(lastEventId) && lastEventId >= 0) {
    url.searchParams.set("last_event_id", String(Math.floor(lastEventId)));
  }

  return url.toString();
}

export async function listScans(accessToken: string) {
  const payload = await request<unknown>("/api/scans", accessToken, {
    method: "GET",
  });

  return normalizeScans(payload);
}

export async function getScan(accessToken: string, scanId: string) {
  const payload = await request<unknown>(`/api/scans/${encodeURIComponent(scanId)}`, accessToken, {
    method: "GET",
  });

  const scan = normalizeScan(payload);
  if (!scan) {
    throw new Error("Scan not found.");
  }

  return scan;
}

export async function listScanEvents(accessToken: string, scanId: string) {
  const payload = await request<unknown>(`/api/scans/${encodeURIComponent(scanId)}/events`, accessToken, {
    method: "GET",
  });

  return normalizeEvents(payload);
}

export async function appendScanEvent(accessToken: string, scanId: string, input: AppendScanEventInput) {
  return request<unknown>(`/api/scans/${encodeURIComponent(scanId)}/events`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      event_type: input.eventType,
      data: input.data ?? {},
    }),
  });
}

export async function createScan(accessToken: string, input: CreateScanInput) {
  return request<unknown>("/api/scans", accessToken, {
    method: "POST",
    body: JSON.stringify({
      target_url: input.targetUrl,
      url: input.targetUrl,
      scan_mode: input.scanMode ?? "quick",
    }),
  });
}
