import { KEY_NAME, LEASE_PARAM } from '../constants'
import { verifyLease } from '../lease'
import { cacheKeyFor, serveFromR2 } from '../r2'
import type { Env } from '../types'

/** 2. Guard key.bin: verify the timed HMAC lease, then serve (cached, lease-agnostic key). */
export async function serveKey(
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