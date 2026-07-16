package io.splinters.mediashield.config;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Immutable runtime configuration for the Media Shield.
 *
 * <p>Every mutator returns a new instance; the live config is swapped atomically in
 * {@code MediaShieldExtension} so handler threads always read a consistent snapshot.
 */
public final class ShieldConfig {

    private final boolean enabled;
    private final boolean blindProxyBrowser;   // rewrite client-facing copy in the Proxy
    private final boolean blindOtherTools;     // belt-and-braces: Repeater/Logger/etc. render paths
    private final boolean rewriteInlineMedia;  // strip data: URIs / inline svg in html & css
    private final boolean blindWebSockets;     // blind media in proxied WebSocket frames
    private final boolean harvestMetadata;     // extract EXIF/GPS/dimensions/hashes
    private final boolean scrubHistory;        // ALSO replace the logged copy -> raw bytes never persisted
    private final Set<String> excludedHosts;   // hosts to leave untouched (noise, e.g. analytics pixels)

    private ShieldConfig(boolean enabled,
                         boolean blindProxyBrowser,
                         boolean blindOtherTools,
                         boolean rewriteInlineMedia,
                         boolean blindWebSockets,
                         boolean harvestMetadata,
                         boolean scrubHistory,
                         Set<String> excludedHosts) {
        this.enabled = enabled;
        this.blindProxyBrowser = blindProxyBrowser;
        this.blindOtherTools = blindOtherTools;
        this.rewriteInlineMedia = rewriteInlineMedia;
        this.blindWebSockets = blindWebSockets;
        this.harvestMetadata = harvestMetadata;
        this.scrubHistory = scrubHistory;
        this.excludedHosts = Collections.unmodifiableSet(new LinkedHashSet<>(excludedHosts));
    }

    /**
     * Safe, thorough defaults: shield on, everything blinded, metadata harvested. History
     * retention is ON by default (originals kept for findings). Enable {@link #scrubHistory()}
     * for material that must never touch disk.
     */
    public static ShieldConfig defaults() {
        return new ShieldConfig(true, true, true, true, true, true, false, new LinkedHashSet<>());
    }

    public boolean enabled() { return enabled; }
    public boolean blindProxyBrowser() { return blindProxyBrowser; }
    public boolean blindOtherTools() { return blindOtherTools; }
    public boolean rewriteInlineMedia() { return rewriteInlineMedia; }
    public boolean blindWebSockets() { return blindWebSockets; }
    public boolean harvestMetadata() { return harvestMetadata; }
    public boolean scrubHistory() { return scrubHistory; }
    public Set<String> excludedHosts() { return excludedHosts; }

    /** True when the given host should be shielded (i.e. not on the exclude list). */
    public boolean appliesToHost(String host) {
        if (host == null) {
            return true;
        }
        String h = host.toLowerCase();
        for (String excluded : excludedHosts) {
            String e = excluded.toLowerCase();
            if (h.equals(e) || h.endsWith("." + e)) {
                return false;
            }
        }
        return true;
    }

    public ShieldConfig withEnabled(boolean value) {
        return new ShieldConfig(value, blindProxyBrowser, blindOtherTools, rewriteInlineMedia, blindWebSockets, harvestMetadata, scrubHistory, excludedHosts);
    }

    public ShieldConfig withBlindProxyBrowser(boolean value) {
        return new ShieldConfig(enabled, value, blindOtherTools, rewriteInlineMedia, blindWebSockets, harvestMetadata, scrubHistory, excludedHosts);
    }

    public ShieldConfig withBlindOtherTools(boolean value) {
        return new ShieldConfig(enabled, blindProxyBrowser, value, rewriteInlineMedia, blindWebSockets, harvestMetadata, scrubHistory, excludedHosts);
    }

    public ShieldConfig withRewriteInlineMedia(boolean value) {
        return new ShieldConfig(enabled, blindProxyBrowser, blindOtherTools, value, blindWebSockets, harvestMetadata, scrubHistory, excludedHosts);
    }

    public ShieldConfig withBlindWebSockets(boolean value) {
        return new ShieldConfig(enabled, blindProxyBrowser, blindOtherTools, rewriteInlineMedia, value, harvestMetadata, scrubHistory, excludedHosts);
    }

    public ShieldConfig withHarvestMetadata(boolean value) {
        return new ShieldConfig(enabled, blindProxyBrowser, blindOtherTools, rewriteInlineMedia, blindWebSockets, value, scrubHistory, excludedHosts);
    }

    public ShieldConfig withScrubHistory(boolean value) {
        return new ShieldConfig(enabled, blindProxyBrowser, blindOtherTools, rewriteInlineMedia, blindWebSockets, harvestMetadata, value, excludedHosts);
    }

    public ShieldConfig withExcludedHosts(Set<String> hosts) {
        return new ShieldConfig(enabled, blindProxyBrowser, blindOtherTools, rewriteInlineMedia, blindWebSockets, harvestMetadata, scrubHistory, hosts);
    }
}
