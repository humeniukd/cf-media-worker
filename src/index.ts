/**
 * media-worker — same-origin HLS gateway in front of the `media` R2 bucket.
 *
 * Bucket layout: `<uid>/media.m3u8`, `<uid>/init.mp4`, `<uid>/seg*.m4s`, `<uid>/key.bin`.
 * The segments and `init.mp4` are already AES-encrypted, so they are served openly.
 * Only `key.bin` is guarded — clients must present a time-limited HMAC lease that this
 * Worker both *mints* (when rewriting the playlist) and *verifies* (when serving the key),
 * using the exact `is_timed_hmac_valid_v0` scheme so a Cloudflare WAF rule could enforce it
 * identically at the edge if desired. The playlist route is itself gated by a `__Secure-stream`
 * cookie carrying the same kind of token, minted elsewhere over `<clientId><uid>`.
 *
 *   1. GET /<uid>/media.m3u8?clientId=<id> — requires a `__Secure-stream=<ts>-<mac>` cookie
 *      valid for `<clientId><uid>`, then fetches the playlist from R2 and appends
 *      `?lease=<ts>-<mac>` to the `#EXT-X-KEY` URI (the key.bin reference). Cached per client
 *      IP (CF-Connecting-IP); repeat requests from the same IP reuse one cached playlist +
 *      lease. Falls back to no-store when the client IP is unknown (e.g. local dev).
 *   2. GET /<uid>/key.bin?lease=<ts>-<mac> — verify the lease, then serve the key.
 *   3. GET /<uid>/<segment> — serve the encrypted segment.
 *
 * key.bin and segments are cached in the Cloudflare Cache API for LEASE_TTL (2h), keyed by
 * a URL with the volatile `lease` param stripped so every valid listener shares one entry.
 *
 * See src/constants.ts (route file names), src/lease.ts (token scheme), src/cors.ts,
 * src/cookies.ts, src/r2.ts (cached R2 reads) and src/routes/* (per-route handlers).
 */

import { KEY_NAME, PLAYLIST_NAME } from './constants'
import { corsHeaders, withCors } from './cors'
import { serveAsset } from './routes/asset'
import { serveKey } from './routes/key'
import { servePlaylist } from './routes/playlist'
import type { Env } from './types'

export type { Env }

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