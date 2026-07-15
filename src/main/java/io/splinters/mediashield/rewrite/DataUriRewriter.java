package io.splinters.mediashield.rewrite;

import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.placeholder.OrangePlaceholder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Replaces inline {@code data:} media URIs (base64 or url-encoded) with an orange placeholder
 * data URI. This is the ONLY path by which embedded media reaches a viewer without generating
 * its own HTTP response, so it is the piece the Content-Type swap cannot catch. Applies equally
 * to HTML ({@code src}, {@code srcset}, {@code style}, inline SVG) and CSS ({@code url(...)}).
 */
public final class DataUriRewriter {

    // data:image/png;base64,AAAA...  — capture the media class so we can label the placeholder.
    private static final Pattern DATA_URI = Pattern.compile(
            "data:(image|video|audio)/[a-z0-9.+-]+(;[a-z0-9-]+=[^,;\"')\\s]+)*(;base64)?,"
                    + "[a-zA-Z0-9+/=._~:@!$&'*+,;%\\-]*",
            Pattern.CASE_INSENSITIVE);

    private DataUriRewriter() {
    }

    public static boolean containsMediaDataUri(String body) {
        return body != null && DATA_URI.matcher(body).find();
    }

    public static String rewrite(String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        Matcher m = DATA_URI.matcher(body);
        StringBuilder out = new StringBuilder(body.length());
        while (m.find()) {
            MediaKind kind = switch (m.group(1).toLowerCase()) {
                case "video" -> MediaKind.VIDEO;
                case "audio" -> MediaKind.AUDIO;
                default -> MediaKind.IMAGE;
            };
            m.appendReplacement(out, Matcher.quoteReplacement(OrangePlaceholder.dataUri(kind)));
        }
        m.appendTail(out);
        return out.toString();
    }
}
