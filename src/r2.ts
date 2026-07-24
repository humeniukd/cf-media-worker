import { LEASE_PARAM } from './constants'
import { LEASE_TTL } from './lease'
import type { Env } from './types'

/** Edge/browser cache lifetime for guarded key + public segments. */
export const CACHE_TTL = LEASE_TTL

/** Build a stable cache key (drops `lease`) reusing the request method/headers. */
export function cacheKeyFor(url: URL): URL {
    const key = new URL(url.toString())
    key.searchParams.delete(LEASE_PARAM)
    return key
}

/** Serve an R2 object through the Cache API. The full body is always cached for CACHE_TTL. */
export async function serveFromR2(
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