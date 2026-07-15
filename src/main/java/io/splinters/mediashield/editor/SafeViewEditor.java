package io.splinters.mediashield.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.metadata.MediaMetadata;
import io.splinters.mediashield.metadata.MetadataExtractor;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Font;

/**
 * A read-only, TEXT-ONLY editor tab shown on media responses. It renders the harvested metadata
 * (type, dimensions, hashes, EXIF/GPS) as plain text and never draws a pixel of the asset. It is
 * the safe alternative to Burp's native "Render" tab — the one surface this extension cannot
 * remove — giving the analyst somewhere deliberate to look.
 */
public final class SafeViewEditor implements ExtensionProvidedHttpResponseEditor {

    private final JTextArea textArea;
    private final JScrollPane scrollPane;
    private HttpResponse currentResponse;

    public SafeViewEditor() {
        this.textArea = new JTextArea();
        this.textArea.setEditable(false);
        this.textArea.setLineWrap(true);
        this.textArea.setWrapStyleWord(true);
        this.textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.scrollPane = new JScrollPane(textArea);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }
        HttpResponse response = requestResponse.response();
        MediaKind kind = MediaDetector.classify(
                response.headerValue("Content-Type"), response.body().getBytes());
        return kind.isMedia();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentResponse = requestResponse == null ? null : requestResponse.response();
        if (currentResponse == null) {
            textArea.setText("");
            return;
        }
        String url = requestResponse.request() != null ? requestResponse.request().url() : "(unknown)";
        String method = requestResponse.request() != null ? requestResponse.request().method() : "-";

        MediaMetadata meta = MetadataExtractor.extract(
                url, method, currentResponse.statusCode(),
                currentResponse.headerValue("Content-Type"),
                currentResponse.body().getBytes());

        textArea.setText(render(meta));
        textArea.setCaretPosition(0);
    }

    private String render(MediaMetadata m) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== MEDIA SHIELD — metadata only, no preview ===\n\n");
        sb.append("URL              : ").append(m.url()).append('\n');
        sb.append("Method / Status  : ").append(m.httpMethod()).append("  ").append(m.statusCode()).append('\n');
        sb.append("Declared type    : ").append(nz(m.declaredContentType())).append('\n');
        sb.append("Sniffed type     : ").append(nz(m.sniffedType())).append('\n');
        if (m.typeMismatch()) {
            sb.append("  !! TYPE MISMATCH — declared vs. actual differ (possible polyglot/type confusion)\n");
        }
        sb.append("Size             : ").append(m.byteLength()).append(" bytes\n");
        sb.append("Dimensions       : ").append(m.dimensionText()).append('\n');
        sb.append("SHA-256          : ").append(nz(m.sha256())).append('\n');
        sb.append("MD5              : ").append(nz(m.md5())).append('\n');
        if (m.hasGps()) {
            sb.append("GPS              : ").append(m.gpsText())
              .append("   (https://www.google.com/maps?q=").append(m.gpsText().replace(" ", "")).append(")\n");
        }
        if (!m.notableTags().isEmpty()) {
            sb.append("\n-- Notable tags --\n");
            for (String t : m.notableTags()) {
                sb.append("  ").append(t).append('\n');
            }
        }
        if (m.capturedText() != null && !m.capturedText().isBlank()) {
            sb.append("\n-- Full metadata dump --\n");
            sb.append(m.capturedText());
        } else {
            sb.append("\n(No embedded EXIF/XMP/IPTC metadata found or body not image-parseable.)\n");
        }
        return sb.toString();
    }

    private static String nz(String s) {
        return (s == null || s.isBlank()) ? "(none)" : s;
    }

    @Override
    public HttpResponse getResponse() {
        // View-only: never mutate the message.
        return currentResponse;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public Selection selectedData() {
        String sel = textArea.getSelectedText();
        return sel == null ? null : Selection.selection(ByteArray.byteArray(sel));
    }

    @Override
    public String caption() {
        return "Media Shield 🛡";
    }

    @Override
    public Component uiComponent() {
        return scrollPane;
    }
}
