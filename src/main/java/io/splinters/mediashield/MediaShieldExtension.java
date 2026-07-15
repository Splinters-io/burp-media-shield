package io.splinters.mediashield;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.editor.SafeViewEditorProvider;
import io.splinters.mediashield.http.MediaHttpHandler;
import io.splinters.mediashield.metadata.MetadataStore;
import io.splinters.mediashield.proxy.MediaProxyHandler;
import io.splinters.mediashield.ui.ShieldSettingsPanel;

/**
 * Entry point. Registers, in order:
 * <ol>
 *   <li>a Proxy response handler that blinds the browser while keeping originals in history;</li>
 *   <li>a cross-tool HTTP handler that blinds Repeater/Logger renders (belt-and-braces);</li>
 *   <li>a text-only "Media Shield" response editor tab (safe alternative to native Render);</li>
 *   <li>a "Media Shield" suite tab with toggles, counters and the harvested-metadata table.</li>
 * </ol>
 */
public final class MediaShieldExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Media Shield");

        ConfigHolder configHolder = new ConfigHolder(ShieldConfig.defaults());
        MetadataStore metadataStore = new MetadataStore();

        api.proxy().registerResponseHandler(
                new MediaProxyHandler(configHolder, metadataStore, api.logging()));

        api.http().registerHttpHandler(
                new MediaHttpHandler(configHolder, metadataStore, api.logging()));

        api.userInterface().registerHttpResponseEditorProvider(new SafeViewEditorProvider());

        api.userInterface().registerSuiteTab(
                "Media Shield", new ShieldSettingsPanel(configHolder, metadataStore));

        api.logging().logToOutput(
                "Media Shield loaded. Browser + Repeater/Logger renders are blinded; "
                        + "Proxy history retains original bytes & metadata. "
                        + "Tune behaviour in the 'Media Shield' tab.");
    }
}
