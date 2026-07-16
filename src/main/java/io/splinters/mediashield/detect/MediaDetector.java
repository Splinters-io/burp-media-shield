package io.splinters.mediashield.detect;

/**
 * Classifies a response as media using BOTH the declared Content-Type and the actual
 * leading bytes (magic numbers). Either signal alone is enough to shield — this defeats
 * type-confusion tricks (an image served as text/plain, or a polyglot) in both directions.
 */
public final class MediaDetector {

    private MediaDetector() {
    }

    /** Classify from the Content-Type header value alone (may be null/blank). */
    public static MediaKind fromContentType(String contentType) {
        if (contentType == null) {
            return MediaKind.NONE;
        }
        String ct = contentType.toLowerCase();
        int semi = ct.indexOf(';');
        if (semi >= 0) {
            ct = ct.substring(0, semi);
        }
        ct = ct.trim();

        if (ct.equals("image/svg+xml")) {
            return MediaKind.SVG;
        }
        if (ct.startsWith("image/")) {
            return MediaKind.IMAGE;
        }
        if (ct.startsWith("video/")) {
            return MediaKind.VIDEO;
        }
        if (ct.startsWith("audio/")) {
            return MediaKind.AUDIO;
        }
        // Common streaming-media manifests & segment containers.
        if (ct.equals("application/vnd.apple.mpegurl")   // HLS .m3u8
                || ct.equals("application/x-mpegurl")
                || ct.equals("application/dash+xml")      // MPEG-DASH .mpd
                || ct.equals("video/mp2t")                // .ts segments
                || ct.equals("application/mp4")) {
            return MediaKind.VIDEO;
        }
        return MediaKind.NONE;
    }

    /** Classify from magic bytes. Returns NONE if nothing recognisable. */
    public static MediaKind fromMagicBytes(byte[] body) {
        if (body == null || body.length < 12) {
            return MediaKind.NONE;
        }

        // ---- Images ----
        if (starts(body, 0xFF, 0xD8, 0xFF)) {
            return MediaKind.IMAGE;                                    // JPEG
        }
        if (starts(body, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) {
            return MediaKind.IMAGE;                                    // PNG
        }
        if (starts(body, 0x47, 0x49, 0x46, 0x38)) {
            return MediaKind.IMAGE;                                    // GIF8
        }
        if (starts(body, 0x42, 0x4D)) {
            return MediaKind.IMAGE;                                    // BMP
        }
        if (ascii(body, 0, "RIFF") && ascii(body, 8, "WEBP")) {
            return MediaKind.IMAGE;                                    // WebP
        }
        if (starts(body, 0x00, 0x00, 0x01, 0x00) || starts(body, 0x00, 0x00, 0x02, 0x00)) {
            return MediaKind.IMAGE;                                    // ICO / CUR
        }
        if (ascii(body, 4, "ftypheic") || ascii(body, 4, "ftypheix")
                || ascii(body, 4, "ftypmif1") || ascii(body, 4, "ftypavif")) {
            return MediaKind.IMAGE;                                    // HEIC / HEIF / AVIF
        }
        if (starts(body, 0x49, 0x49, 0x2A, 0x00) || starts(body, 0x4D, 0x4D, 0x00, 0x2A)) {
            return MediaKind.IMAGE;                                    // TIFF (le/be)
        }

        // ---- Video / audio containers ----
        if (ascii(body, 4, "ftyp")) {
            // ISO-BMFF family: mp4, mov, m4v (video) and m4a (audio).
            if (ascii(body, 8, "M4A")) {
                return MediaKind.AUDIO;
            }
            return MediaKind.VIDEO;                                    // mp4/mov/m4v
        }
        if (ascii(body, 0, "RIFF") && ascii(body, 8, "AVI ")) {
            return MediaKind.VIDEO;                                    // AVI
        }
        if (starts(body, 0x1A, 0x45, 0xDF, 0xA3)) {
            return MediaKind.VIDEO;                                    // Matroska / WebM
        }
        if (starts(body, 0x46, 0x4C, 0x56, 0x01)) {
            return MediaKind.VIDEO;                                    // FLV
        }

        if (ascii(body, 0, "OggS")) {
            return MediaKind.AUDIO;                                    // Ogg (audio bias)
        }
        if (ascii(body, 0, "fLaC")) {
            return MediaKind.AUDIO;                                    // FLAC
        }
        if (ascii(body, 0, "ID3") || starts(body, 0xFF, 0xFB) || starts(body, 0xFF, 0xF3)) {
            return MediaKind.AUDIO;                                    // MP3
        }
        if (ascii(body, 0, "RIFF") && ascii(body, 8, "WAVE")) {
            return MediaKind.AUDIO;                                    // WAV
        }

        // ---- SVG (text) ----
        String head = new String(body, 0, Math.min(body.length, 512),
                java.nio.charset.StandardCharsets.US_ASCII).toLowerCase();
        if (head.contains("<svg")) {
            return MediaKind.SVG;
        }

        return MediaKind.NONE;
    }

    /**
     * Combined verdict. Header wins when it names a concrete media type; otherwise magic
     * bytes decide. SVG from either signal maps to SVG so it is rewritten, not swapped.
     */
    public static MediaKind classify(String contentType, byte[] body) {
        MediaKind byHeader = fromContentType(contentType);
        MediaKind byBytes = fromMagicBytes(body);

        if (byHeader == MediaKind.SVG || byBytes == MediaKind.SVG) {
            return MediaKind.SVG;
        }
        if (byHeader.isBinaryMedia()) {
            return byHeader;
        }
        if (byBytes.isBinaryMedia()) {
            return byBytes;
        }
        return MediaKind.NONE;
    }

    /**
     * Concrete raster image format from magic bytes, as a lowercase token ("png", "jpeg", "gif",
     * "bmp", "webp", "tiff", "ico", "heic", "avif") or {@code null} if not a recognised raster.
     * Used by WebSocket blinding, where there is no Content-Type header and the replacement must be
     * a real image in the SAME format the page's JavaScript expects.
     */
    public static String imageFormat(byte[] body) {
        if (body == null || body.length < 12) {
            return null;
        }
        if (starts(body, 0xFF, 0xD8, 0xFF)) return "jpeg";
        if (starts(body, 0x89, 0x50, 0x4E, 0x47)) return "png";
        if (starts(body, 0x47, 0x49, 0x46, 0x38)) return "gif";
        if (starts(body, 0x42, 0x4D)) return "bmp";
        if (ascii(body, 0, "RIFF") && ascii(body, 8, "WEBP")) return "webp";
        if (starts(body, 0x49, 0x49, 0x2A, 0x00) || starts(body, 0x4D, 0x4D, 0x00, 0x2A)) return "tiff";
        if (starts(body, 0x00, 0x00, 0x01, 0x00)) return "ico";
        if (ascii(body, 4, "ftypheic") || ascii(body, 4, "ftypheix") || ascii(body, 4, "ftypmif1")) return "heic";
        if (ascii(body, 4, "ftypavif")) return "avif";
        return null;
    }

    private static boolean starts(byte[] body, int... prefix) {
        if (body.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if ((body[i] & 0xFF) != (prefix[i] & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    private static boolean ascii(byte[] body, int offset, String marker) {
        if (body.length < offset + marker.length()) {
            return false;
        }
        for (int i = 0; i < marker.length(); i++) {
            if ((body[offset + i] & 0xFF) != marker.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
