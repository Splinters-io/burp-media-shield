package io.splinters.mediashield.rewrite;

import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.placeholder.RasterPlaceholder;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds RAW base64-encoded media embedded in a text payload (e.g. a JSON field like
 * {@code {"image":"/9j/4AAQ..."}}) — the common way media rides a WebSocket — and swaps it for
 * base64 of a format-matched orange raster.
 *
 * <p>False positives are avoided structurally: a candidate run is only replaced if it actually
 * <em>decodes</em> to bytes whose magic number is a known image format. Session tokens, JWT parts
 * and IDs decode to non-media bytes and are left untouched.
 */
public final class Base64MediaRewriter {

    /** Minimum run length to consider — long enough to hold a small image, short enough to catch thumbnails. */
    private static final int MIN_LEN = 64;

    private static final Pattern BASE64_RUN =
            Pattern.compile("[A-Za-z0-9+/]{" + MIN_LEN + ",}={0,2}");

    private Base64MediaRewriter() {
    }

    /** Result of a scan: rewritten text, whether anything changed, and the decoded media found. */
    public record Result(String text, boolean changed, List<byte[]> extractedMedia) {
    }

    public static Result rewrite(String text) {
        if (text == null || text.isEmpty()) {
            return new Result(text, false, List.of());
        }
        Matcher m = BASE64_RUN.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        List<byte[]> extracted = new ArrayList<>();
        boolean changed = false;

        while (m.find()) {
            String run = m.group();
            byte[] decoded = tryDecode(run);
            String format = decoded == null ? null : MediaDetector.imageFormat(decoded);
            if (format != null) {
                extracted.add(decoded);
                m.appendReplacement(out, Matcher.quoteReplacement(RasterPlaceholder.base64(format)));
                changed = true;
            } else {
                m.appendReplacement(out, Matcher.quoteReplacement(run));
            }
        }
        m.appendTail(out);
        return new Result(out.toString(), changed, extracted);
    }

    private static byte[] tryDecode(String run) {
        try {
            return Base64.getDecoder().decode(run);
        } catch (IllegalArgumentException strict) {
            try {
                return Base64.getMimeDecoder().decode(run);
            } catch (IllegalArgumentException lenient) {
                return null;
            }
        }
    }
}
