package io.splinters.mediashield.http;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;
import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.metadata.MetadataStore;
import io.splinters.mediashield.rewrite.ResponseRewriter;
import io.splinters.mediashield.rewrite.RewriteResult;

import java.util.EnumSet;
import java.util.Set;

/**
 * Belt-and-braces blinding for tools that render but do NOT flow through the Proxy path.
 *
 * <p>Deliberately scoped: it blinds only the manual, human-viewed render surfaces (Repeater,
 * Logger). It explicitly skips:
 * <ul>
 *   <li>{@code PROXY} — handled non-destructively by {@code MediaProxyHandler} so history keeps
 *       original bytes;</li>
 *   <li>{@code SCANNER}/{@code INTRUDER}/{@code EXTENSIONS} — automated analysis that must see
 *       real bytes (media-parsing bugs, SSRF-via-fetch, payload reflection).</li>
 * </ul>
 * Metadata is still harvested here before rewriting, so nothing is lost even where a tool's Raw
 * view now shows the placeholder — the pristine capture lives in the Media Metadata tab.
 */
public final class MediaHttpHandler implements HttpHandler {

    private static final Set<ToolType> BLINDED_TOOLS =
            EnumSet.of(ToolType.REPEATER, ToolType.LOGGER, ToolType.ORGANIZER);

    private final ConfigHolder configHolder;
    private final MetadataStore metadataStore;
    private final Logging logging;

    public MediaHttpHandler(ConfigHolder configHolder, MetadataStore metadataStore, Logging logging) {
        this.configHolder = configHolder;
        this.metadataStore = metadataStore;
        this.logging = logging;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        ShieldConfig config = configHolder.get();
        if (!config.enabled() || !config.blindOtherTools()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        if (!BLINDED_TOOLS.contains(responseReceived.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String host = responseReceived.initiatingRequest().httpService().host();
        if (!config.appliesToHost(host)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        try {
            String url = responseReceived.initiatingRequest().url();
            String method = responseReceived.initiatingRequest().method();

            RewriteResult result = new ResponseRewriter(config).apply(responseReceived, url, method);

            result.metadata().forEach(metadataStore::record);
            if (result.changed()) {
                metadataStore.incrementShielded();
                return ResponseReceivedAction.continueWith(result.response());
            }
        } catch (Throwable t) {
            logging.logToError("Media Shield (http) error, passing original: " + t);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
