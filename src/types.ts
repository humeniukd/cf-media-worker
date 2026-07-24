export interface Env {
    /** R2 bucket binding — the `media` bucket. */
    MEDIA: R2Bucket
    /** Shared secret for the lease HMAC. Must match `is_timed_hmac_valid_v0` key + the app. */
    MEDIA_TOKEN_SECRET: string
    /**
     * Comma-separated list of origins allowed to read these streams cross-origin
     * (e.g. `https://app.example.com,https://admin.example.com`). A single `*`
     * allows any origin. Unset/empty disables CORS entirely (same-origin only).
     */
    ALLOWED_ORIGINS?: string
}
