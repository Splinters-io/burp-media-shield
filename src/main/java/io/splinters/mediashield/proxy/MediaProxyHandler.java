package io.splinters.mediashield.proxy;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.metadata.MetadataStore;
import io.splinters.mediashield.rewrite.ResponseRewriter;
import io.splinters.mediashield.rewrite.RewriteResult;

/**
 * The primary shield. Runs in the Proxy path — which carries ALL browser traffic (Burp's embedded
 * browser or any browser proxied through Burp).
 *
 * <p>Critically, the media swap happens in {@link #handleResponseToBeSent} (the client-facing
 * stage) and NOT in {@link #handleResponseReceived} (the logged stage). Burp therefore records the
 * ORIGINAL, untouched response in Proxy history — pristine bytes, real headers, full EXIF — while
 * the browser only ever receives the orange placeholder. "Capture everything, render nothing."
 */
public final class MediaProxyHandler implements ProxyResponseHandler {

    private final ConfigHolder configHolder;
    private final MetadataStore metadataStore;
    private final Logging logging;

    public MediaProxyHandler(ConfigHolder configHolder, MetadataStore metadataStore, Logging logging) {
        this.configHolder = configHolder;
        this.metadataStore = metadataStore;
        this.logging = logging;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        ShieldConfig config = configHolder.get();

        // Default: leave the logged copy pristine — this is what the analyst reads metadata from,
        // and it is what Burp persists in the project file.
        if (!config.enabled() || !config.scrubHistory()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // NO-RETENTION MODE: replace the logged copy too, so the original media bytes never reach
        // the Burp project file on disk. Metadata is harvested from the live bytes first (text
        // only: hashes, dimensions, EXIF) and kept in memory — the raw asset is not retained.
        String host = interceptedResponse.initiatingRequest().httpService().host();
        if (!config.appliesToHost(host)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        try {
            String url = interceptedResponse.initiatingRequest().url();
            String method = interceptedResponse.initiatingRequest().method();
            RewriteResult result = new ResponseRewriter(config).apply(interceptedResponse, url, method);
            if (result.metadata() != null) {
                metadataStore.record(result.metadata());
            }
            if (result.changed()) {
                metadataStore.incrementShielded();
                return ProxyResponseReceivedAction.continueWith(result.response());
            }
        } catch (Throwable t) {
            logging.logToError("Media Shield (scrub-history) error, passing original: " + t);
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        ShieldConfig config = configHolder.get();
        if (!config.enabled() || !config.blindProxyBrowser()) {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }

        String host = interceptedResponse.initiatingRequest().httpService().host();
        if (!config.appliesToHost(host)) {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }

        try {
            String url = interceptedResponse.initiatingRequest().url();
            String method = interceptedResponse.initiatingRequest().method();

            RewriteResult result = new ResponseRewriter(config).apply(interceptedResponse, url, method);

            if (result.metadata() != null) {
                metadataStore.record(result.metadata());
            }
            if (result.changed()) {
                metadataStore.incrementShielded();
                return ProxyResponseToBeSentAction.continueWith(result.response());
            }
        } catch (Throwable t) {
            // Never let the shield break traffic: on any error, forward the original untouched.
            logging.logToError("Media Shield (proxy) error, passing original: " + t);
        }
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
