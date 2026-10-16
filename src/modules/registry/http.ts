/**
 * Small HTTP helpers for the public npm and OSV APIs: timeout, one retry on transient
 * failures, a size cap, and errors that say which upstream failed.
 */

export class UpstreamError extends Error {
  constructor(
    readonly upstream: string,
    message: string,
    readonly status?: number,
  ) {
    super(`${upstream}: ${message}`);
    this.name = 'UpstreamError';
  }
}

export interface FetchOptions {
  timeoutMs?: number;
  /** Reject bodies larger than this many bytes. */
  maxBytes?: number;
  method?: 'GET' | 'POST';
  body?: unknown;
  headers?: Record<string, string>;
}

const USER_AGENT = 'dep-bouncer (+https://github.com/harsha31bs07-blip/dep-bouncer)';
const RETRYABLE = new Set([429, 500, 502, 503, 504]);

/** Returns the response body as bytes, or null on HTTP 404. */
export async function fetchBytes(
  upstream: string,
  url: string,
  opts: FetchOptions = {},
): Promise<Uint8Array | null> {
  const { timeoutMs = 15_000, maxBytes = 64 * 1024 * 1024, method = 'GET' } = opts;
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, {
        method,
        headers: {
          'user-agent': USER_AGENT,
          ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...opts.headers,
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 404) return null;
      if (!res.ok) {
        lastError = new UpstreamError(upstream, `HTTP ${res.status}`, res.status);
        if (RETRYABLE.has(res.status)) continue;
        throw lastError;
      }
      const declared = Number(res.headers.get('content-length') ?? 0);
      if (declared > maxBytes) {
        throw new UpstreamError(upstream, `response too large (${declared} bytes)`);
      }
      const buf = new Uint8Array(await res.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new UpstreamError(upstream, `response too large (${buf.byteLength} bytes)`);
      }
      return buf;
    } catch (err) {
      if (err instanceof UpstreamError && !RETRYABLE.has(err.status ?? 0)) throw err;
      lastError = err;
    }
  }
  if (lastError instanceof UpstreamError) throw lastError;
  const reason = lastError instanceof Error ? lastError.message : String(lastError);
  throw new UpstreamError(upstream, reason);
}

/** Fetches and parses JSON, or returns null on HTTP 404. */
export async function fetchJson<T>(
  upstream: string,
  url: string,
  opts: FetchOptions = {},
): Promise<T | null> {
  const bytes = await fetchBytes(upstream, url, opts);
  if (bytes === null) return null;
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    throw new UpstreamError(upstream, 'invalid JSON response');
  }
}
