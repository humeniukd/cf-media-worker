/* ------------------------------------------------------------------ *
 * is_timed_hmac_valid_v0 token scheme
 *
 * MessageMAC layout (what Cloudflare's WAF parses):
 *   <message><separator><timestamp>-<base64(HMAC-SHA256(key, message + timestamp))>
 *
 * Here `message` is the resource being leased (e.g. `/<uid>/key.bin`, or `<clientId><uid>`
 * for the playlist cookie), the timestamp is 10-digit unix-seconds, and the MAC is standard
 * base64 (URL-encoded in transit). We sign/verify exactly this so an edge WAF rule can
 * validate the same token unchanged.
 * ------------------------------------------------------------------ */

/** Lease validity, in seconds. Mirrors the WAF rule's `validity` argument. */
export const LEASE_TTL = 7200 // 2h
/** Tolerated clock skew when a lease timestamp is slightly in the future. */
const CLOCK_SKEW = 60

export async function signLease(message: string, secret: string): Promise<string> {
    const timestamp = Math.floor(Date.now() / 1000).toString()
    const mac = await hmacBase64(secret, message + timestamp)
    return `${timestamp}-${mac}`
}

export async function verifyLease(message: string, token: string, secret: string): Promise<boolean> {
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