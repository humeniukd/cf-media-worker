/** Read a single cookie value from the request's `Cookie` header. */
export function getCookie(request: Request, name: string): string | null {
    const header = request.headers.get('Cookie')
    if (!header) return null
    for (const part of header.split(';')) {
        const eq = part.indexOf('=')
        if (eq < 0) continue
        if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim())
    }
    return null
}