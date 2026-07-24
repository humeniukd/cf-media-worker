/** Bucket layout: `<uid>/media.m3u8`, `<uid>/init.mp4`, `<uid>/seg*.m4s`, `<uid>/key.bin`. */
export const PLAYLIST_NAME = 'media.m3u8'
export const KEY_NAME = 'key.bin'
/** Query param carrying the `is_timed_hmac_valid_v0` lease token for key.bin. */
export const LEASE_PARAM = 'lease'