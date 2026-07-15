package io.splinters.mediashield.config;

import java.util.function.UnaryOperator;

/**
 * Holds the live {@link ShieldConfig} behind a volatile reference. Handler threads read the
 * current snapshot per call; the UI publishes new immutable configs. No locking needed — reads
 * and reference swaps are atomic, and {@code ShieldConfig} is immutable.
 */
public final class ConfigHolder {

    private volatile ShieldConfig config;

    public ConfigHolder(ShieldConfig initial) {
        this.config = initial;
    }

    public ShieldConfig get() {
        return config;
    }

    public void set(ShieldConfig next) {
        this.config = next;
    }

    /** Apply an immutable transform and publish the result. */
    public void update(UnaryOperator<ShieldConfig> mutator) {
        this.config = mutator.apply(this.config);
    }
}
