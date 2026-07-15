package io.splinters.mediashield.metadata;

import java.util.List;

/**
 * Immutable snapshot of everything we could learn about a media asset WITHOUT rendering it.
 * This is the analyst-facing deliverable: enough to write a finding, never a pixel.
 */
public record MediaMetadata(
        String url,
        String httpMethod,
        short statusCode,
        String declaredContentType,   // what the server said
        String sniffedType,           // what the bytes actually are
        int byteLength,
        String sha256,
        String md5,
        int width,                    // -1 if unknown
        int height,                   // -1 if unknown
        boolean hasGps,
        String gpsText,               // "lat, lon" or null
        String capturedText,          // full flattened EXIF/XMP/IPTC dump (may be empty)
        List<String> notableTags      // headline tags surfaced in the summary
) {
    public boolean typeMismatch() {
        if (declaredContentType == null || sniffedType == null || sniffedType.isBlank()) {
            return false;
        }
        return !declaredContentType.toLowerCase().contains(sniffedType.toLowerCase());
    }

    public String dimensionText() {
        return (width > 0 && height > 0) ? width + " x " + height + " px" : "unknown";
    }
}
