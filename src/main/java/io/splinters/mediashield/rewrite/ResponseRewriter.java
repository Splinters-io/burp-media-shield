package io.splinters.mediashield.rewrite;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.metadata.MediaMetadata;
import io.splinters.mediashield.metadata.MetadataExtractor;
import io.splinters.mediashield.placeholder.OrangePlaceholder;

/**
 * Core shield logic over a single Montoya {@link HttpResponse}. Given the response and the
 * request context (url/method), it decides whether the body is media and returns a client-facing
 * replacement, while harvesting metadata from the ORIGINAL bytes first.
 *
 * <p>Pure with respect to Burp state: it only reads the response and returns a new one, so it can
 * be driven from any handler (Proxy, or the cross-tool HttpHandler) without side effects beyond
 * the returned {@link RewriteResult}.
 */
public final class ResponseRewriter {

    private static final String SHIELD_HEADER = "X-Media-Shield";

    private final ShieldConfig config;

    public ResponseRewriter(ShieldConfig config) {
        this.config = config;
    }

    public RewriteResult apply(HttpResponse response, String url, String method) {
        if (response == null) {
            return RewriteResult.unchanged(response);
        }

        // Already shielded earlier in the chain (e.g. scrubbed in handleResponseReceived, now
        // seen again in handleResponseToBeSent, or handled by another registered handler).
        if (response.hasHeader(SHIELD_HEADER)) {
            return RewriteResult.unchanged(response);
        }

        byte[] body = response.body().getBytes();
        String contentType = response.headerValue("Content-Type");
        MediaKind kind = MediaDetector.classify(contentType, body);

        // ---- Binary media: swap the whole body for an orange SVG stand-in. ----
        if (kind.isBinaryMedia()) {
            MediaMetadata metadata = config.harvestMetadata()
                    ? MetadataExtractor.extract(url, method, response.statusCode(), contentType, body)
                    : null;
            HttpResponse shielded = replaceWithPlaceholder(response, kind);
            return new RewriteResult(shielded, true, metadata);
        }

        // ---- SVG: it's XML; rewrite embedded rasters and cover with an orange rect. ----
        if (kind == MediaKind.SVG) {
            String rewritten = OrangePlaceholder.svgOverlay(response.bodyToString());
            HttpResponse shielded = response
                    .withBody(rewritten)
                    .withUpdatedHeader(SHIELD_HEADER, "svg-overlaid");
            MediaMetadata metadata = config.harvestMetadata()
                    ? MetadataExtractor.extract(url, method, response.statusCode(), contentType, body)
                    : null;
            return new RewriteResult(shielded, true, metadata);
        }

        // ---- Text carriers: neutralise inline data: URIs / inline media (HTML & CSS). ----
        if (config.rewriteInlineMedia() && isTextCarrier(contentType)) {
            String original = response.bodyToString();
            if (DataUriRewriter.containsMediaDataUri(original) || looksLikeHtml(contentType)) {
                String rewritten = looksLikeHtml(contentType)
                        ? HtmlMediaRewriter.rewrite(original)
                        : DataUriRewriter.rewrite(original);
                if (!rewritten.equals(original)) {
                    HttpResponse shielded = response
                            .withBody(rewritten)
                            .withUpdatedHeader(SHIELD_HEADER, "inline-neutralised");
                    return new RewriteResult(shielded, true, null);
                }
            }
        }

        return RewriteResult.unchanged(response);
    }

    private HttpResponse replaceWithPlaceholder(HttpResponse response, MediaKind kind) {
        HttpResponse shielded = response
                .withBody(ByteArray.byteArray(OrangePlaceholder.svgBytes(kind)))
                .withStatusCode((short) 200)                              // drop 206 partial-content semantics
                .withUpdatedHeader("Content-Type", OrangePlaceholder.svgContentType())
                .withUpdatedHeader(SHIELD_HEADER, "replaced-" + kind.name().toLowerCase());

        // Strip headers that describe the ORIGINAL bytes and would now be wrong/harmful.
        shielded = removeHeader(shielded, "Content-Encoding");   // our SVG is plaintext
        shielded = removeHeader(shielded, "Content-Range");      // no longer a byte range
        shielded = removeHeader(shielded, "Accept-Ranges");
        shielded = removeHeader(shielded, "Content-Disposition"); // avoid "download" of stale name
        return shielded;
    }

    private HttpResponse removeHeader(HttpResponse response, String name) {
        if (response.hasHeader(name)) {
            return response.withRemovedHeader(name);
        }
        return response;
    }

    private static boolean isTextCarrier(String contentType) {
        if (contentType == null) {
            return false;
        }
        String ct = contentType.toLowerCase();
        return ct.contains("text/html")
                || ct.contains("application/xhtml")
                || ct.contains("text/css");
    }

    private static boolean looksLikeHtml(String contentType) {
        if (contentType == null) {
            return false;
        }
        String ct = contentType.toLowerCase();
        return ct.contains("text/html") || ct.contains("application/xhtml");
    }
}
