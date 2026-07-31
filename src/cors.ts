import type { Env } from './types'

/**
 * Resolve the CORS response headers for a request. The matching request `Origin`
 * is echoed back (or `*` when any origin is allowed) so credentialed and cached
 * responses stay correct; `Vary: Origin` keeps shared caches from leaking one
 * origin's allow-header to another.
 */
export function corsHeaders(request: Request, env: Env): Headers {
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

    headers.set('Access-Control-Allow-Credentials', 'true')
    headers.set('Cross-Origin-Resource-Policy', 'same-site')
    headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
    headers.set('Access-Control-Expose-Headers', 'Content-Length, ETag')
    headers.set('Access-Control-Max-Age', '86400')
    return headers
}

/** Merge CORS headers onto a response (cloned so cached/immutable responses stay writable). */
export function withCors(response: Response, cors: Headers): Response {
    if ([...cors.keys()].length === 0) return response
    const merged = new Response(response.body, response)
    cors.forEach((value, key) => merged.headers.append(key, value))
    return merged
}