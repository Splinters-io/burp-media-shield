package io.splinters.mediashield.export;

import io.splinters.mediashield.metadata.MediaMetadata;

import java.util.List;

/**
 * Renders harvested {@link MediaMetadata} to RFC-4180 CSV text.
 *
 * <p>Pure and immutable: takes a snapshot, returns a String. Two safety concerns are handled
 * because this data is attacker-controlled (URLs, EXIF fields come from the target):
 * <ul>
 *   <li><b>CSV quoting</b> — any field with a comma, quote or newline is double-quoted and inner
 *       quotes are doubled.</li>
 *   <li><b>CSV / formula injection</b> — a field beginning with {@code = + - @} (or tab/CR) is
 *       prefixed with a single quote so spreadsheet apps don't execute it on open.</li>
 * </ul>
 */
public final class CsvExporter {

    private static final String[] HEADERS = {
            "URL", "Method", "Status", "Declared-Content-Type", "Sniffed-Type", "Type-Mismatch",
            "Bytes", "Width", "Height", "Dimensions", "Has-GPS", "GPS", "SHA-256", "MD5",
            "Notable-Tags", "Full-Metadata"
    };

    private CsvExporter() {
    }

    public static String toCsv(List<MediaMetadata> rows) {
        StringBuilder sb = new StringBuilder();
        appendRow(sb, HEADERS);
        for (MediaMetadata m : rows) {
            appendRow(sb, new String[]{
                    m.url(),
                    m.httpMethod(),
                    String.valueOf(m.statusCode()),
                    m.declaredContentType(),
                    m.sniffedType(),
                    m.typeMismatch() ? "YES" : "",
                    String.valueOf(m.byteLength()),
                    m.width() > 0 ? String.valueOf(m.width()) : "",
                    m.height() > 0 ? String.valueOf(m.height()) : "",
                    m.dimensionText(),
                    m.hasGps() ? "YES" : "",
                    m.hasGps() ? m.gpsText() : "",
                    m.sha256(),
                    m.md5(),
                    m.notableTags() == null ? "" : String.join("; ", m.notableTags()),
                    m.capturedText()
            });
        }
        return sb.toString();
    }

    private static void appendRow(StringBuilder sb, String[] fields) {
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(escape(fields[i]));
        }
        sb.append("\r\n");
    }

    private static String escape(String raw) {
        String value = raw == null ? "" : raw;

        // Neutralise formula/CSV injection before any quoting decision.
        if (!value.isEmpty()) {
            char first = value.charAt(0);
            if (first == '=' || first == '+' || first == '-' || first == '@'
                    || first == '\t' || first == '\r') {
                value = "'" + value;
            }
        }

        boolean mustQuote = value.contains(",") || value.contains("\"")
                || value.contains("\n") || value.contains("\r");
        if (mustQuote) {
            return '"' + value.replace("\"", "\"\"") + '"';
        }
        return value;
    }
}
