package io.splinters.mediashield.websocket;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.metadata.MetadataStore;

/**
 * Attaches a {@link MediaWebSocketHandler} to every WebSocket the Proxy creates, capturing the
 * upgrade request so each socket's traffic is labelled with its URL/host for scoping and metadata.
 */
public final class MediaWebSocketCreationHandler implements ProxyWebSocketCreationHandler {

    private final ConfigHolder configHolder;
    private final MetadataStore store;
    private final Logging logging;

    public MediaWebSocketCreationHandler(ConfigHolder configHolder, MetadataStore store, Logging logging) {
        this.configHolder = configHolder;
        this.store = store;
        this.logging = logging;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        String host;
        String label;
        try {
            host = webSocketCreation.upgradeRequest().httpService().host();
            label = webSocketCreation.upgradeRequest().url();
        } catch (Throwable t) {
            host = null;
            label = "(websocket)";
        }
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(
                new MediaWebSocketHandler(configHolder, store, logging, host, label));
    }
}
