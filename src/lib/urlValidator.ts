const ASSET_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff", "avif",
  "css", "js", "mjs", "cjs", "jsx", "tsx", "map",
  "woff", "woff2", "ttf", "eot", "otf",
  "mp4", "webm", "ogg", "mp3", "wav", "flac", "aac", "m4a",
  "json", "xml", "txt", "pdf", "zip", "gz", "tar"
]);

/**
 * Validates that a candidate URL is a genuine monitored web destination,
 * and rejects browser internals, dashboard/API self-traffic, and static page assets.
 */
export function isValidMonitoredUrl(rawUrl: string, serverHost?: string): boolean {
  if (!rawUrl || typeof rawUrl !== "string") return false;
  const trimmed = rawUrl.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return false;

  try {
    const parsed = new URL(trimmed);
    const host = parsed.hostname.toLowerCase();

    // Browser internal / extension URL schemes
    if (
      trimmed.startsWith("chrome://") ||
      trimmed.startsWith("chrome-extension://") ||
      trimmed.startsWith("edge://") ||
      trimmed.startsWith("about:") ||
      trimmed.startsWith("data:") ||
      trimmed.startsWith("blob:")
    ) {
      return false;
    }

    // Exclude PhishGuard Server self-traffic if host matches
    if (serverHost) {
      const cleanServerHost = serverHost.toLowerCase().split(":")[0];
      if (host === cleanServerHost) {
        return false;
      }
    }

    // Exclude PhishGuard dashboard/API routes regardless of domain
    const pathname = parsed.pathname.toLowerCase();
    if (
      pathname.startsWith("/api/") ||
      pathname === "/api" ||
      pathname.startsWith("/download-extension") ||
      pathname.startsWith("/extension/") ||
      pathname.startsWith("/warning") ||
      pathname === "/health" ||
      pathname === "/info"
    ) {
      return false;
    }

    // Exclude static assets by file extension
    const lastSlash = pathname.lastIndexOf("/");
    const filename = lastSlash !== -1 ? pathname.slice(lastSlash + 1) : pathname;
    const lastDot = filename.lastIndexOf(".");
    if (lastDot !== -1 && lastDot < filename.length - 1) {
      const ext = filename.slice(lastDot + 1).toLowerCase();
      if (ASSET_EXTENSIONS.has(ext)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}
