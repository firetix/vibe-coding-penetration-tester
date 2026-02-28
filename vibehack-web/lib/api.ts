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

export type CreateScanInput = {
  targetUrl: string;
  scanMode?: string;
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

export async function listScans(accessToken: string) {
  const payload = await request<unknown>("/api/scans", accessToken, {
    method: "GET",
  });

  return normalizeScans(payload);
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
