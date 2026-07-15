package io.splinters.mediashield.ui;

import io.splinters.mediashield.config.ConfigHolder;
import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.metadata.MediaMetadata;
import io.splinters.mediashield.metadata.MetadataStore;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.Timer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The "Media Shield" suite tab: live toggles, running counters, host exclude-list, and the table
 * of harvested media metadata. All controls publish immutable configs into the {@link ConfigHolder}
 * so handler threads pick them up on their next request.
 */
public final class ShieldSettingsPanel extends JPanel {

    private static final String[] COLUMNS =
            {"URL", "Declared", "Sniffed", "Bytes", "Dimensions", "GPS", "SHA-256"};

    private final ConfigHolder configHolder;
    private final MetadataStore store;

    private final JLabel statsLabel = new JLabel();
    private final DefaultTableModel tableModel;

    public ShieldSettingsPanel(ConfigHolder configHolder, MetadataStore store) {
        this.configHolder = configHolder;
        this.store = store;
        this.tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildControls(), buildTable());
        split.setResizeWeight(0.35);
        add(split, BorderLayout.CENTER);

        startRefreshTimer();
    }

    private JPanel buildControls() {
        ShieldConfig cfg = configHolder.get();
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Media Shield — capture everything, render nothing");
        title.setFont(title.getFont().deriveFont(title.getFont().getSize2D() + 4f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(title);
        panel.add(Box.createVerticalStrut(4));

        JLabel blurb = new JLabel("<html>Replaces images / video / audio with bright-orange "
                + "placeholders in every view an analyst looks at, while Proxy history keeps the "
                + "original bytes and full metadata for your findings.</html>");
        blurb.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(blurb);
        panel.add(Box.createVerticalStrut(10));

        panel.add(checkbox("Shield ENABLED (master switch)", cfg.enabled(),
                v -> configHolder.update(c -> c.withEnabled(v))));
        panel.add(checkbox("Blind the browser (Proxy path) — original kept in history",
                cfg.blindProxyBrowser(), v -> configHolder.update(c -> c.withBlindProxyBrowser(v))));
        panel.add(checkbox("Blind Repeater / Logger render (belt-and-braces)",
                cfg.blindOtherTools(), v -> configHolder.update(c -> c.withBlindOtherTools(v))));
        panel.add(checkbox("Neutralise inline data: URIs & inline SVG in HTML/CSS",
                cfg.rewriteInlineMedia(), v -> configHolder.update(c -> c.withRewriteInlineMedia(v))));
        panel.add(checkbox("Harvest metadata (EXIF / GPS / dimensions / hashes)",
                cfg.harvestMetadata(), v -> configHolder.update(c -> c.withHarvestMetadata(v))));

        panel.add(Box.createVerticalStrut(8));
        JLabel retentionWarn = new JLabel("<html><b>Data retention:</b> by default original media "
                + "bytes are kept in Proxy history and <u>written to the Burp project file on disk</u> "
                + "(not rendered, but forensically present). Enable the option below for material that "
                + "must never touch disk.</html>");
        retentionWarn.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(retentionWarn);
        panel.add(checkbox("NO-RETENTION MODE — also scrub originals from history (keep text metadata only)",
                cfg.scrubHistory(), v -> configHolder.update(c -> c.withScrubHistory(v))));

        panel.add(Box.createVerticalStrut(10));
        panel.add(leftLabel("Excluded hosts (one per line — left fully untouched):"));
        JTextArea excludes = new JTextArea(String.join("\n", cfg.excludedHosts()), 4, 40);
        excludes.setAlignmentX(Component.LEFT_ALIGNMENT);
        JScrollPane excludeScroll = new JScrollPane(excludes);
        excludeScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        excludeScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        panel.add(excludeScroll);

        JButton applyHosts = new JButton("Apply exclude list");
        applyHosts.setAlignmentX(Component.LEFT_ALIGNMENT);
        applyHosts.addActionListener(e -> {
            Set<String> hosts = new LinkedHashSet<>();
            for (String line : excludes.getText().split("\\R")) {
                String h = line.trim();
                if (!h.isEmpty()) {
                    hosts.add(h);
                }
            }
            configHolder.update(c -> c.withExcludedHosts(hosts));
        });
        panel.add(applyHosts);

        panel.add(Box.createVerticalStrut(10));
        statsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(statsLabel);

        return panel;
    }

    private JPanel buildTable() {
        JPanel wrap = new JPanel(new BorderLayout(4, 4));
        JLabel header = new JLabel("Harvested media (metadata captured from original bytes):");
        wrap.add(header, BorderLayout.NORTH);

        JTable table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        wrap.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshTable());
        JButton clear = new JButton("Clear captured");
        clear.addActionListener(e -> {
            store.clear();
            refreshTable();
        });
        buttons.add(refresh);
        buttons.add(clear);
        wrap.add(buttons, BorderLayout.SOUTH);
        return wrap;
    }

    private void startRefreshTimer() {
        Timer timer = new Timer(2000, e -> {
            updateStats();
            refreshTable();
        });
        timer.setRepeats(true);
        timer.start();
        updateStats();
    }

    private void updateStats() {
        statsLabel.setText(String.format(
                "<html><b>%d</b> media items shielded &nbsp;|&nbsp; <b>%d</b> metadata records captured</html>",
                store.shieldedCount(), store.recordedCount()));
    }

    private void refreshTable() {
        List<MediaMetadata> snapshot = store.snapshot();
        tableModel.setRowCount(0);
        for (MediaMetadata m : snapshot) {
            tableModel.addRow(new Object[]{
                    m.url(),
                    m.declaredContentType(),
                    m.sniffedType(),
                    m.byteLength(),
                    m.dimensionText(),
                    m.hasGps() ? m.gpsText() : "",
                    m.sha256()
            });
        }
    }

    private JCheckBox checkbox(String label, boolean selected, BoolConsumer onChange) {
        JCheckBox box = new JCheckBox(label, selected);
        box.setAlignmentX(Component.LEFT_ALIGNMENT);
        box.addActionListener(e -> onChange.accept(box.isSelected()));
        return box;
    }

    private JLabel leftLabel(String text) {
        JLabel l = new JLabel(text);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
    }

    @FunctionalInterface
    private interface BoolConsumer {
        void accept(boolean value);
    }
}
