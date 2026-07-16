package io.splinters.mediashield.websocket;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.websocket.Direction;
import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.metadata.MetadataStore;
import io.splinters.mediashield.rewrite.WsMediaRewriter;

/**
 * Blinds media carried over a single proxied WebSocket. Mirrors the HTTP design:
 * only SERVER_TO_CLIENT frames (content heading for the analyst's browser) are touched, and the
 * received/to-be-sent split preserves originals in WebSockets history.
 *
 * <ul>
 *   <li>Retention ON (default): work at the <b>to-be-sent</b> stage — the browser gets the orange
 *       raster, history keeps the original frame for metadata.</li>
 *   <li>No-Retention mode: work at the <b>received</b> stage — the logged frame is scrubbed too, so
 *       raw media never lands in the project file. Metadata is harvested first, in memory.</li>
 * </ul>
 * Outbound (CLIENT_TO_SERVER) frames are left pristine so upload/testing behaviour is unaffected.
 */
public final class MediaWebSocketHandler implements ProxyMessageHandler {

    private final ConfigHolder configHolder;
    private final MetadataStore store;
    private final Logging logging;
    private final String host;
    private final String label;

    public MediaWebSocketHandler(ConfigHolder configHolder, MetadataStore store, Logging logging,
                                 String host, String label) {
        this.configHolder = configHolder;
        this.store = store;
        this.logging = logging;
        this.host = host;
        this.label = label;
    }

    // ---------------- text ----------------

    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
        if (shouldHandleAt(true, message.direction())) {
            String rewritten = tryRewriteText(message.payload());
            if (rewritten != null) {
                return TextMessageReceivedAction.continueWith(rewritten);
            }
        }
        return TextMessageReceivedAction.continueWith(message.payload());
    }

    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
        if (shouldHandleAt(false, message.direction())) {
            String rewritten = tryRewriteText(message.payload());
            if (rewritten != null) {
                return TextMessageToBeSentAction.continueWith(rewritten);
            }
        }
        return TextMessageToBeSentAction.continueWith(message.payload());
    }

    // ---------------- binary ----------------

    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
        if (shouldHandleAt(true, message.direction())) {
            ByteArray rewritten = tryRewriteBinary(message.payload());
            if (rewritten != null) {
                return BinaryMessageReceivedAction.continueWith(rewritten);
            }
        }
        return BinaryMessageReceivedAction.continueWith(message.payload());
    }

    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
        if (shouldHandleAt(false, message.direction())) {
            ByteArray rewritten = tryRewriteBinary(message.payload());
            if (rewritten != null) {
                return BinaryMessageToBeSentAction.continueWith(rewritten);
            }
        }
        return BinaryMessageToBeSentAction.continueWith(message.payload());
    }

    // ---------------- helpers ----------------

    /**
     * The received stage handles iff No-Retention mode is on; otherwise the to-be-sent stage does.
     * This guarantees each frame is transformed exactly once and, when retaining, keeps the logged
     * copy pristine.
     */
    private boolean shouldHandleAt(boolean receivedStage, Direction direction) {
        ShieldConfig config = configHolder.get();
        if (!config.enabled() || !config.blindWebSockets()) {
            return false;
        }
        if (direction != Direction.SERVER_TO_CLIENT) {
            return false;
        }
        if (!config.appliesToHost(host)) {
            return false;
        }
        return receivedStage == config.scrubHistory();
    }

    private String tryRewriteText(String payload) {
        try {
            WsMediaRewriter.TextResult result =
                    new WsMediaRewriter(configHolder.get()).rewriteText(payload, label + " [WS text]");
            result.metadata().forEach(store::record);
            if (result.changed()) {
                store.incrementShielded();
                return result.payload();
            }
        } catch (Throwable t) {
            logging.logToError("Media Shield (ws text) error, passing original: " + t);
        }
        return null;
    }

    private ByteArray tryRewriteBinary(ByteArray payload) {
        try {
            WsMediaRewriter.BinaryResult result =
                    new WsMediaRewriter(configHolder.get()).rewriteBinary(payload.getBytes(), label + " [WS binary]");
            if (result.metadata() != null) {
                store.record(result.metadata());
            }
            if (result.changed()) {
                store.incrementShielded();
                return ByteArray.byteArray(result.payload());
            }
        } catch (Throwable t) {
            logging.logToError("Media Shield (ws binary) error, passing original: " + t);
        }
        return null;
    }
}
