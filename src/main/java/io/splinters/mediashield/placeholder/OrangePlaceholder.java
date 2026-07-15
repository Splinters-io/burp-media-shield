package io.splinters.mediashield.placeholder;

import io.splinters.mediashield.detect.MediaKind;

import java.nio.charset.StandardCharsets;

/**
 * Generates the bright-orange stand-in that replaces hidden media.
 *
 * <p>The stand-in is an SVG served as {@code image/svg+xml}. Because it declares
 * {@code width/height=100%} with {@code preserveAspectRatio="none"}, browsers stretch it to
 * fill whatever box the original element defined, so page layout is preserved regardless of
 * the source media's intrinsic dimensions. An {@code <img>} pointing at a swapped response
 * renders these bytes fine — browsers key off the response Content-Type, not the URL.
 */
public final class OrangePlaceholder {

    /** Bright, unmistakable "safety orange". */
    private static final String ORANGE = "#FF6A00";
    private static final String ORANGE_DARK = "#C24E00";
    private static final String INK = "#1A1200";

    private OrangePlaceholder() {
    }

    /** Data-URI form for inline substitution inside HTML/CSS ({@code data:image/svg+xml;base64,...}). */
    public static String dataUri(MediaKind kind) {
        String b64 = java.util.Base64.getEncoder()
                .encodeToString(svg(kind).getBytes(StandardCharsets.UTF_8));
        return "data:image/svg+xml;base64," + b64;
    }

    /** Raw SVG bytes to use as a replacement response body. */
    public static byte[] svgBytes(MediaKind kind) {
        return svg(kind).getBytes(StandardCharsets.UTF_8);
    }

    /** Content-Type to pair with {@link #svgBytes}. */
    public static String svgContentType() {
        return "image/svg+xml";
    }

    /**
     * Covers an existing (untrusted) SVG document with a full-viewport orange rect + label,
     * so inline vector art and any embedded rasters are hidden without having to parse the SVG.
     * A {@code width/height=100%} rect resolves against the SVG viewport regardless of its
     * internal viewBox, so it blankets whatever is underneath.
     */
    public static String svgOverlay(String originalSvg) {
        String cover = """
                <g><rect x="0" y="0" width="100%%" height="100%%" fill="%s"/>\
                <rect x="0" y="0" width="100%%" height="100%%" fill="none" stroke="%s" \
                stroke-width="4"/><text x="50%%" y="50%%" font-family="monospace" \
                font-size="16" font-weight="bold" text-anchor="middle" \
                dominant-baseline="central" fill="%s">VECTOR HIDDEN</text></g>"""
                .formatted(ORANGE, ORANGE_DARK, INK);

        if (originalSvg == null) {
            return svg(MediaKind.SVG);
        }
        int close = originalSvg.lastIndexOf("</svg>");
        if (close < 0) {
            // Not a well-formed SVG we can wrap; fall back to a clean placeholder.
            return svg(MediaKind.SVG);
        }
        return originalSvg.substring(0, close) + cover + originalSvg.substring(close);
    }

    private static String svg(MediaKind kind) {
        String label = switch (kind) {
            case VIDEO -> "VIDEO HIDDEN";
            case AUDIO -> "AUDIO HIDDEN";
            case SVG -> "VECTOR HIDDEN";
            default -> "IMAGE HIDDEN";
        };
        String glyph = switch (kind) {
            case VIDEO -> "&#9658;";   // play triangle
            case AUDIO -> "&#9834;";   // musical note
            default -> "&#9632;";      // solid square
        };

        // viewBox gives an internal coordinate space; preserveAspectRatio=none fills the host box.
        return """
                <svg xmlns="http://www.w3.org/2000/svg" width="100%%" height="100%%" \
                viewBox="0 0 400 300" preserveAspectRatio="none" role="img" \
                aria-label="%s">
                  <defs>
                    <pattern id="h" width="28" height="28" patternUnits="userSpaceOnUse" \
                patternTransform="rotate(45)">
                      <rect width="28" height="28" fill="%s"/>
                      <rect width="14" height="28" fill="%s"/>
                    </pattern>
                  </defs>
                  <rect width="400" height="300" fill="url(#h)"/>
                  <rect x="8" y="8" width="384" height="284" fill="none" \
                stroke="%s" stroke-width="6"/>
                  <text x="200" y="150" font-family="monospace" font-size="120" \
                text-anchor="middle" dominant-baseline="central" fill="%s">%s</text>
                  <text x="200" y="250" font-family="monospace" font-size="26" font-weight="bold" \
                text-anchor="middle" dominant-baseline="central" fill="%s">%s</text>
                </svg>
                """.formatted(label, ORANGE, ORANGE_DARK, INK, INK, glyph, INK, label);
    }
}
