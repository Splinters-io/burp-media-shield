package io.splinters.mediashield.detect;

/** Coarse classification of a response body for shielding decisions. */
public enum MediaKind {
    IMAGE,
    VIDEO,
    AUDIO,
    SVG,     // xml-based image: handled by body rewrite, not a binary swap
    NONE;

    public boolean isMedia() {
        return this != NONE;
    }

    /** True when the body is opaque binary we replace wholesale (vs. text we rewrite in place). */
    public boolean isBinaryMedia() {
        return this == IMAGE || this == VIDEO || this == AUDIO;
    }
}
