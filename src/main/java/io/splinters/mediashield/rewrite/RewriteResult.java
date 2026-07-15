package io.splinters.mediashield.rewrite;

import burp.api.montoya.http.message.responses.HttpResponse;
import io.splinters.mediashield.metadata.MediaMetadata;

/** Outcome of a shield pass: the (possibly rewritten) response plus any harvested metadata. */
public record RewriteResult(HttpResponse response, boolean changed, MediaMetadata metadata) {

    public static RewriteResult unchanged(HttpResponse response) {
        return new RewriteResult(response, false, null);
    }
}
