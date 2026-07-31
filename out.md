Handle three behaviors

1. Generates the HMAC signature for key.bin — GET /<uid>/media.m3u8 fetches the playlist from R2 and rewrites only the #EXT-X-KEY URI to key.bin?lease=<ts>-<mac>. Playlist is per-listener.
2. Guards key.bin via is_timed_hmac_valid_v0 — GET /<uid>/key.bin?lease=… parses the <timestamp>-<base64mac> token, recomputes HMAC-SHA256(secret, "/<uid>/key.bin" +         
   timestamp), constant-time compares, and checks the 2h window (with 60s skew tolerance). Invalid/expired → 403. This matches the WAF format exactly, so an edge rule is        
   optional rather than required.
3. Cloudflare Cache API, 2h — key.bin and segments are stored in caches.default with max-age=7200. The cache key strips the volatile lease param so all valid listeners share
   one entry (and the lease is still re-verified on every request before the cached key is returned). Range requests bypass the cache and stream straight from R2 as 206.

I confirmed the token format against current Cloudflare docs: <message><separator><timestamp>-<base64(HMAC-SHA256(key, message+timestamp))>, separator ?lease= (length 7),    
10-digit timestamp — so the WAF expression would be is_timed_hmac_valid_v0($STREAM_TOKEN_SECRET, http.request.uri, 7200, http.request.timestamp.sec, 7).

To run it

cd media-worker && npm install                                                                                                                                                
wrangler secret put STREAM_TOKEN_SECRET   # same value as the app's .env                                                                                                       
npm run dev --remote     # or: npm run deploy