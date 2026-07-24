import { cacheKeyFor, serveFromR2 } from '../r2'
import type { Env } from '../types'

/** 3. Serve a public encrypted asset (init.mp4 / *.m4s), cached. */
export function serveAsset(
    request: Request,
    url: URL,
    objectKey: string,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    return serveFromR2(request, cacheKeyFor(url), objectKey, env, ctx, false)
}