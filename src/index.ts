/**
 * media-worker — same-origin HLS gateway in front of the `media` R2 bucket.
 *
 * Bucket layout: `<uid>/media.m3u8`, `<uid>/init.mp4`, `<uid>/seg*.m4s`, `<uid>/key.bin`.
 * The segments and `init.mp4` are already AES-encrypted, so they are served openly.
 * Only `key.bin` is guarded — clients must present a time-limited HMAC lease that this
 * Worker both *mints* (when rewriting the playlist) and *verifies* (when serving the key),
 * using the exact `is_timed_hmac_valid_v0` scheme so a Cloudflare WAF rule could enforce it
 * identically at the edge if desired.
 *
 *   1. GET /<uid>/media.m3u8 — fetch playlist from R2, append `?lease=<ts>-<mac>` to the
 *      `#EXT-X-KEY` URI (the key.bin reference). Cached per client IP (CF-Connecting-IP);
 *      repeat requests from the same IP reuse one cached playlist + lease. Falls back to
 *      no-store when the client IP is unknown (e.g. local dev).
 *   2. GET /<uid>/key.bin?lease=<ts>-<mac> — verify the lease, then serve the key.
 *   3. GET /<uid>/<segment> — serve the encrypted segment.
 *
 * key.bin and segments are cached in the Cloudflare Cache API for LEASE_TTL (2h), keyed by
 * a URL with the volatile `lease` param stripped so every valid listener shares one entry.
 */

export interface Env {
    /** R2 bucket binding — the `media` bucket. */
    MEDIA: R2Bucket
    /** Shared secret for the lease HMAC. Must match `is_timed_hmac_valid_v0` key + the app. */
    MEDIA_TOKEN_SECRET: string
    /**
     * Comma-separated list of origins allowed to read these streams cross-origin
     * (e.g. `https://app.example.com,https://admin.example.com`). A single `*`
     * allows any origin. Unset/empty disables CORS entirely (same-origin only).
     */
    ALLOWED_ORIGINS?: string
}

const PLAYLIST_NAME = 'media.m3u8'
const KEY_NAME = 'key.bin'
const LEASE_PARAM = 'lease'
/** Synthetic cache-key param carrying the client IP (never sent to clients). */
const PLAYLIST_CACHE_PARAM = 'ip'

/** Lease validity, in seconds. Mirrors the WAF rule's `validity` argument. */
const LEASE_TTL = 7200 // 2h
/** Tolerated clock skew when a lease timestamp is slightly in the future. */
const CLOCK_SKEW = 60
/** Edge/browser cache lifetime for guarded key + public segments. */
const CACHE_TTL = LEASE_TTL
/**
 * Playlist cache lifetime. Strictly less than LEASE_TTL, so a lease embedded in a cached
 * playlist always has ample validity left when served on a late cache-hit.
 */
const PLAYLIST_CACHE_TTL = LEASE_TTL / 2 // 1h

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const cors = corsHeaders(request, env)

        // CORS preflight — answer before any routing/auth.
        if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors })

        if (request.method !== 'GET' && request.method !== 'HEAD')
            return withCors(new Response('Method Not Allowed', { status: 405 }), cors)

        const url = new URL(request.url)
        // `/<uid>/<file>` — uid may itself contain slashes only if the bucket does; keep it simple.
        const match = url.pathname.match(/^\/([^/]+)\/(.+)$/)
        if (!match) return withCors(new Response('Not Found', { status: 404 }), cors)

        const [, uid, file] = match
        const objectKey = `${uid}/${file}`

        const response =
            file === PLAYLIST_NAME
                ? await servePlaylist(request, url, uid, objectKey, env, ctx)
                : file === KEY_NAME
                  ? await serveKey(request, url, uid, objectKey, env, ctx)
                  : await serveAsset(request, url, objectKey, env, ctx)

        return withCors(response, cors)
    },
} satisfies ExportedHandler<Env>

/**
 * Resolve the CORS response headers for a request. The matching request `Origin`
 * is echoed back (or `*` when any origin is allowed) so credentialed and cached
 * responses stay correct; `Vary: Origin` keeps shared caches from leaking one
 * origin's allow-header to another.
 */
function corsHeaders(request: Request, env: Env): Headers {
    const headers = new Headers()
    const allowed = (env.ALLOWED_ORIGINS ?? '')
        .split(',')
        .map((o) => o.trim())
        .filter(Boolean)
    if (allowed.length === 0) return headers

    const origin = request.headers.get('Origin')
    const allowAny = allowed.includes('*')
    if (allowAny && !origin) {
        headers.set('Access-Control-Allow-Origin', '*')
    } else if (origin && (allowAny || allowed.includes(origin))) {
        headers.set('Access-Control-Allow-Origin', origin)
        headers.append('Vary', 'Origin')
    } else {
        return headers // origin isn't allowed — emit no CORS headers
    }

    headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
    headers.set('Access-Control-Expose-Headers', 'Content-Length, ETag')
    headers.set('Access-Control-Max-Age', '86400')
    return headers
}

/** Merge CORS headers onto a response (cloned so cached/immutable responses stay writable). */
function withCors(response: Response, cors: Headers): Response {
    if ([...cors.keys()].length === 0) return response
    const merged = new Response(response.body, response)
    cors.forEach((value, key) => merged.headers.append(key, value))
    return merged
}

/**
 * 1. Mint a playlist by leasing only the key.bin URI. The result is cached per client IP
 * (CF-Connecting-IP), so repeat requests from the same client reuse one cached playlist +
 * lease. Falls back to no-store when the client IP is unknown (e.g. local dev).
 */
async function servePlaylist(
    request: Request,
    url: URL,
    uid: string,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    const cache = caches.default

    // Cache per client IP; skip caching when the edge didn't supply one.
    const clientIp = request.headers.get('CF-Connecting-IP')
    const cacheKey = clientIp ? playlistCacheKey(url, clientIp) : null

    if (cacheKey) {
        const cached = await cache.match(cacheKey)
        if (cached) return cached
    }

    const object = await env.MEDIA.get(objectKey)
    if (!object) return new Response('Stream not available', { status: 404 })

    const playlist = await object.text()
    const lease = await signLease(`/${uid}/${KEY_NAME}`, env.MEDIA_TOKEN_SECRET)

    // Append the lease to the #EXT-X-KEY URI only; segment/init URIs stay relative & public.
    const leased = playlist.replace(
        /(#EXT-X-KEY:[^\n]*?URI=")([^"]*)(")/,
        (_m, pre: string, uri: string, post: string) =>
            `${pre}${uri}?${LEASE_PARAM}=${encodeURIComponent(lease)}${post}`
    )

    const response = new Response(leased, {
        headers: {
            'content-type': 'application/vnd.apple.mpegurl',
            'cache-control': cacheKey
                ? // Shared within a cookie group; expires before the embedded lease does.
                  `private, max-age=${PLAYLIST_CACHE_TTL}`
                : // No grouping cookie — per-listener lease must never be shared/cached.
                  'private, no-store',
        },
    })
    if (cacheKey && request.method === 'GET') ctx.waitUntil(cache.put(cacheKey, response.clone()))
    return response
}

/** Cache key for a per-client playlist: the playlist URL tagged with the client IP. */
function playlistCacheKey(url: URL, clientIp: string): URL {
    const key = new URL(url.toString())
    key.searchParams.set(PLAYLIST_CACHE_PARAM, clientIp)
    return key
}

/** 2. Guard key.bin: verify the timed HMAC lease, then serve (cached, lease-agnostic key). */
async function serveKey(
    request: Request,
    url: URL,
    uid: string,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    const token = url.searchParams.get(LEASE_PARAM)
    if (!token || !(await verifyLease(`/${uid}/${KEY_NAME}`, token, env.MEDIA_TOKEN_SECRET)))
        return new Response('Forbidden', { status: 403 })

    // Cache key drops the volatile lease so all valid listeners share one entry.
    return serveFromR2(request, cacheKeyFor(url), objectKey, env, ctx, true)
}

/** 3. Serve a public encrypted asset (init.mp4 / *.m4s), cached. */
function serveAsset(
    request: Request,
    url: URL,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    return serveFromR2(request, cacheKeyFor(url), objectKey, env, ctx, false)
}

/** Build a stable cache key (drops `lease`) reusing the request method/headers. */
function cacheKeyFor(url: URL): URL {
    const key = new URL(url.toString())
    key.searchParams.delete(LEASE_PARAM)
    return key
}

/** Serve an R2 object through the Cache API. The full body is always cached for CACHE_TTL. */
async function serveFromR2(
    request: Request,
    cacheKey: URL,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext,
    isPrivate: boolean
): Promise<Response> {
    const cache = caches.default

    const cached = await cache.match(cacheKey)
    if (cached) return cached

    const object = await env.MEDIA.get(objectKey)
    if (!object) return new Response('Not Found', { status: 404 })

    const headers = new Headers()
    object.writeHttpMetadata(headers)
    headers.set('etag', object.httpEtag)
    headers.set(
        'cache-control',
        `${isPrivate ? 'private' : 'public'}, max-age=${CACHE_TTL}, immutable`
    )
    if (!headers.has('content-type')) headers.set('content-type', 'application/octet-stream')

    const response = new Response(request.method === 'HEAD' ? null : object.body, { headers })
    if (request.method === 'GET') ctx.waitUntil(cache.put(cacheKey, response.clone()))
    return response
}

/* ------------------------------------------------------------------ *
 * is_timed_hmac_valid_v0 token scheme
 *
 * MessageMAC layout (what Cloudflare's WAF parses):
 *   <message><separator><timestamp>-<base64(HMAC-SHA256(key, message + timestamp))>
 *
 * Here `message` is the key's path (`/<uid>/key.bin`), `separator` is `?lease=`, the
 * timestamp is 10-digit unix-seconds, and the MAC is standard base64 (URL-encoded in transit).
 * We sign/verify exactly this so an edge WAF rule can validate the same token unchanged.
 * ------------------------------------------------------------------ */

async function signLease(message: string, secret: string): Promise<string> {
    const timestamp = Math.floor(Date.now() / 1000).toString()
    const mac = await hmacBase64(secret, message + timestamp)
    return `${timestamp}-${mac}`
}

async function verifyLease(message: string, token: string, secret: string): Promise<boolean> {
    const dash = token.indexOf('-')
    if (dash <= 0) return false

    const timestamp = token.slice(0, dash)
    const mac = token.slice(dash + 1)
    if (!/^\d{1,10}$/.test(timestamp) || !mac) return false

    const age = Math.floor(Date.now() / 1000) - Number(timestamp)
    if (age > LEASE_TTL || age < -CLOCK_SKEW) return false

    const expected = await hmacBase64(secret, message + timestamp)
    return timingSafeEqual(mac, expected)
}

async function hmacBase64(secret: string, data: string): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    )
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
    return btoa(String.fromCharCode(...new Uint8Array(sig)))
}

/** Constant-time string compare to avoid leaking the MAC via timing. */
function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
    return diff === 0
}