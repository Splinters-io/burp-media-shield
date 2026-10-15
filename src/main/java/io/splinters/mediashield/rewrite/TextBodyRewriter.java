package io.splinters.mediashield.rewrite;

import java.util.List;

/**
 * Neutralises media embedded in a TEXT response body: {@code data:} URIs, inline SVG/poster frames
 * (HTML only), and raw base64 that decodes to an image.
 *
 * <p>Covers every text type a page's JavaScript can read and turn into a picture, not just the
 * markup the browser renders directly. An API answering {@code {"thumb":"data:image/jpeg;base64,..."}}
 * or {@code {"thumb":"/9j/4AAQ..."}} never produces a media response of its own — the page builds
 * the {@code <img>} client-side — so without this the Content-Type swap never sees it.
 *
 * <p>Pure: no Burp types, so it is unit-testable outside Burp.
 */
public final class TextBodyRewriter {

    private TextBodyRewriter() {
    }

    /** Rewritten text, whether anything changed, and decoded raw-base64 media for metadata. */
    public record Result(String text, boolean changed, List<byte[]> extractedMedia) {
    }

    /** True for text bodies that can carry embedded media. SVG is excluded: it is handled as media. */
    public static boolean isTextCarrier(String contentType) {
        if (contentType == null) {
            return false;
        }
        String ct = mimeType(contentType);
        if (ct.equals("image/svg+xml")) {
            return false;
        }
        return ct.equals("text/html")
                || ct.equals("application/xhtml+xml")
                || ct.equals("text/css")
                || ct.equals("text/plain")
                || ct.equals("application/json") || ct.equals("text/json") || ct.endsWith("+json")
                || ct.equals("application/javascript") || ct.equals("text/javascript")
                || ct.equals("application/x-javascript") || ct.equals("application/ecmascript")
                || ct.equals("application/xml") || ct.equals("text/xml") || ct.endsWith("+xml");
    }

    public static Result rewrite(String contentType, String body) {
        if (body == null || body.isEmpty() || !isTextCarrier(contentType)) {
            return new Result(body, false, List.of());
        }
        String afterInline = looksLikeHtml(contentType)
                ? HtmlMediaRewriter.rewrite(body)
                : DataUriRewriter.rewrite(body);
        Base64MediaRewriter.Result b64 = Base64MediaRewriter.rewrite(afterInline);
        boolean changed = !b64.text().equals(body);
        return new Result(b64.text(), changed, b64.extractedMedia());
    }

    private static boolean looksLikeHtml(String contentType) {
        String ct = mimeType(contentType);
        return ct.equals("text/html") || ct.equals("application/xhtml+xml");
    }

    private static String mimeType(String contentType) {
        String ct = contentType.toLowerCase();
        int semi = ct.indexOf(';');
        return (semi >= 0 ? ct.substring(0, semi) : ct).trim();
    }
}
