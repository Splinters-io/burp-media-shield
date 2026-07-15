package io.splinters.mediashield.metadata;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bounded, thread-safe log of harvested media metadata. Handler threads append; the UI reads
 * snapshots. Oldest entries are evicted past the cap so a long engagement can't exhaust memory.
 */
public final class MetadataStore {

    private static final int MAX_ENTRIES = 5000;

    private final ConcurrentLinkedDeque<MediaMetadata> entries = new ConcurrentLinkedDeque<>();
    private final AtomicInteger size = new AtomicInteger();
    private final AtomicInteger shieldedCount = new AtomicInteger();

    public void record(MediaMetadata metadata) {
        entries.addFirst(metadata);
        if (size.incrementAndGet() > MAX_ENTRIES) {
            if (entries.pollLast() != null) {
                size.decrementAndGet();
            }
        }
    }

    public void incrementShielded() {
        shieldedCount.incrementAndGet();
    }

    public int shieldedCount() {
        return shieldedCount.get();
    }

    public int recordedCount() {
        return size.get();
    }

    /** Newest-first immutable snapshot for the UI. */
    public List<MediaMetadata> snapshot() {
        return new ArrayList<>(entries);
    }

    public void clear() {
        entries.clear();
        size.set(0);
        shieldedCount.set(0);
    }
}
