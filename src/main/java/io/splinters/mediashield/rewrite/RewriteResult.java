package io.splinters.mediashield.rewrite;

import burp.api.montoya.http.message.responses.HttpResponse;
import io.splinters.mediashield.metadata.MediaMetadata;

import java.util.List;

/**
 * Outcome of a shield pass: the (possibly rewritten) response plus any harvested metadata. A list,
 * because one text body can carry several embedded media items.
 */
public record RewriteResult(HttpResponse response, boolean changed, List<MediaMetadata> metadata) {

    public static RewriteResult unchanged(HttpResponse response) {
        return new RewriteResult(response, false, List.of());
    }

    /** Single-item form for whole-body media; {@code metadata} may be null when harvesting is off. */
    public static RewriteResult of(HttpResponse response, MediaMetadata metadata) {
        return new RewriteResult(response, true, metadata == null ? List.of() : List.of(metadata));
    }
}
