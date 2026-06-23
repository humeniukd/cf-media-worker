# media-worker

A standalone Cloudflare Worker that sits directly on top of the `media` R2 bucket and
serves HLS streams with a time-limited key lease — no D1, no app dependency.

Bucket layout per track: `<uid>/media.m3u8`, `<uid>/init.mp4`, `<uid>/seg*.m4s`, `<uid>/key.bin`.
Segments and `init.mp4` are already AES-encrypted, so they're served openly; only `key.bin`
is guarded.

## What it does

1. **Mints** an HMAC lease for `key.bin` when serving `media.m3u8` — rewrites the
   `#EXT-X-KEY` URI to `key.bin?lease=<ts>-<mac>`. The playlist is per-listener and never cached.
2. **Guards** `key.bin` — verifies the lease using the exact `is_timed_hmac_valid_v0`
   scheme before returning the key. Invalid/expired → `403`.
3. **Caches** `key.bin` and segments in the Cloudflare Cache API for **2h** (`CACHE_TTL`),
   keyed with the volatile `lease` param stripped so all valid listeners share one entry.
   Range requests are served straight from R2 (206) and not cached.

The lease TTL (`LEASE_TTL`) and cache TTL are both 2h and live at the top of `src/index.ts`.

## Token scheme (`is_timed_hmac_valid_v0`)

The token embedded in the URL is:

```
<message><separator><timestamp>-<base64(HMAC-SHA256(secret, message + timestamp))>
   │           │          │
   │           │          └─ 10-digit unix seconds
   │           └─ "?lease=" (separator length 7)
   └─ "/<uid>/key.bin"  (the request path)
```

`MEDIA_TOKEN_SECRET` must be identical here, in the main app's `signMediaLease`, and in any
edge WAF rule. Because the Worker verifies the token itself, a WAF rule is **optional** — but
if you add one it would be:

```
is_timed_hmac_valid_v0($MEDIA_TOKEN_SECRET, http.request.uri, 7200, http.request.timestamp.sec, 7)
```

(separator length `7` = `?lease=`).

## Setup

```bash
cd media-worker
npm install
wrangler secret put MEDIA_TOKEN_SECRET   # same value as the main app
npm run typecheck
npm run dev        # local dev (use --remote to hit the real R2 bucket)
npm run deploy
```

For local dev, put the secret in `.dev.vars`:

```
MEDIA_TOKEN_SECRET=<same-as-app>
```

## Notes

- `routes` in `wrangler.jsonc` binds this to `m.loudyo.com` (the app's `MEDIA_CDN`). Remove it
  to use the `*.workers.dev` URL instead.
- The main app's `(api)/[uid]/media.m3u8` route does the same playlist rewrite; this Worker can
  replace it entirely (serve everything from one origin) or run alongside it.