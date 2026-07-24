import { KEY_NAME, LEASE_PARAM } from '../constants'
import { getCookie } from '../cookies'
import { LEASE_TTL, signLease, verifyLease } from '../lease'
import type { Env } from '../types'

/** Synthetic cache-key param carrying the client IP (never sent to clients). */
const PLAYLIST_CACHE_PARAM = 'ip'
/**
 * Playlist cache lifetime. Strictly less than LEASE_TTL, so a lease embedded in a cached
 * playlist always has ample validity left when served on a late cache-hit.
 */
const PLAYLIST_CACHE_TTL = LEASE_TTL / 2 // 1h
/** Cookie gating playlist access. Value is an `is_timed_hmac_valid_v0` token over `<clientId><uid>`. */
const STREAM_COOKIE = '__Secure-stream'
const CLIENT_ID_PARAM = 'clientId'

/**
 * 1. Requires a valid `__Secure-stream` cookie, then mints a playlist by leasing only the
 * key.bin URI. The result is cached per client IP (CF-Connecting-IP), so repeat requests
 * from the same client reuse one cached playlist + lease. Falls back to no-store when the
 * client IP is unknown (e.g. local dev).
 */
export async function servePlaylist(
    request: Request,
    url: URL,
    uid: string,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    const clientId = url.searchParams.get(CLIENT_ID_PARAM) ?? ''
    const cookie = getCookie(request, STREAM_COOKIE)
    if (!cookie || !(await verifyLease(`${clientId}${uid}`, cookie, env.MEDIA_TOKEN_SECRET)))
        return new Response('Forbidden', { status: 403 })

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