package io.splinters.mediashield.rewrite;

import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.metadata.MediaMetadata;
import io.splinters.mediashield.metadata.MetadataExtractor;
import io.splinters.mediashield.placeholder.RasterPlaceholder;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure shield logic for WebSocket frames. Unlike HTTP there is no Content-Type to override, so the
 * replacement must be a real image in the format the page's JavaScript expects — see
 * {@link RasterPlaceholder}. Metadata is harvested from the original bytes first, so nothing is
 * lost even when the frame is scrubbed.
 */
public final class WsMediaRewriter {

    private final ShieldConfig config;

    public WsMediaRewriter(ShieldConfig config) {
        this.config = config;
    }

    public record BinaryResult(byte[] payload, boolean changed, MediaMetadata metadata) {
    }

    public record TextResult(String payload, boolean changed, List<MediaMetadata> metadata) {
    }

    /** Binary frame: swap media for a format-matched orange raster. */
    public BinaryResult rewriteBinary(byte[] payload, String label) {
        MediaKind kind = MediaDetector.classify(null, payload);
        if (!kind.isMedia()) {
            return new BinaryResult(payload, false, null);
        }
        MediaMetadata metadata = config.harvestMetadata()
                ? MetadataExtractor.extract(label, "WS", (short) 0, null, payload)
                : null;

        // Match the raster format when it's an image; video/audio can't be re-encoded as an
        // orange clip, so fall back to an orange PNG (blinds; playback simply breaks).
        String format = MediaDetector.imageFormat(payload);
        byte[] replacement = RasterPlaceholder.bytes(format);   // null format -> PNG fallback
        return new BinaryResult(replacement, true, metadata);
    }

    /** Text frame: neutralise data: URIs and raw base64 media inside JSON/text. */
    public TextResult rewriteText(String payload, String label) {
        if (payload == null || payload.isEmpty()) {
            return new TextResult(payload, false, List.of());
        }
        String afterDataUris = DataUriRewriter.rewrite(payload);
        boolean changed = !afterDataUris.equals(payload);

        Base64MediaRewriter.Result b64 = Base64MediaRewriter.rewrite(afterDataUris);

        List<MediaMetadata> metadata = new ArrayList<>();
        if (config.harvestMetadata()) {
            for (byte[] media : b64.extractedMedia()) {
                metadata.add(MetadataExtractor.extract(label, "WS", (short) 0, null, media));
            }
        }
        return new TextResult(b64.text(), changed || b64.changed(), metadata);
    }
}
