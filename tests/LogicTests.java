import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.placeholder.OrangePlaceholder;
import io.splinters.mediashield.rewrite.DataUriRewriter;
import io.splinters.mediashield.metadata.MediaMetadata;
import io.splinters.mediashield.metadata.MetadataExtractor;
import io.splinters.mediashield.placeholder.RasterPlaceholder;
import io.splinters.mediashield.rewrite.Base64MediaRewriter;
import io.splinters.mediashield.rewrite.WsMediaRewriter;
import io.splinters.mediashield.config.ShieldConfig;

import java.util.Base64;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;

public class LogicTests {
    static int pass = 0, fail = 0;
    static void check(String name, boolean cond) {
        System.out.printf("  [%s] %s%n", cond ? "PASS" : "FAIL", name);
        if (cond) pass++; else fail++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== Detection ==");
        byte[] jpeg = {(byte)0xFF,(byte)0xD8,(byte)0xFF,(byte)0xE0,0,0,0,0,0,0,0,0};
        byte[] png  = {(byte)0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0,0,0,0};
        byte[] mp4  = {0,0,0,0x18,0x66,0x74,0x79,0x70,0x6D,0x70,0x34,0x32}; // ....ftypmp42
        byte[] mp3  = {0x49,0x44,0x33,0x04,0,0,0,0,0,0,0,0};                // ID3
        check("JPEG magic -> IMAGE", MediaDetector.fromMagicBytes(jpeg) == MediaKind.IMAGE);
        check("PNG magic -> IMAGE",  MediaDetector.fromMagicBytes(png)  == MediaKind.IMAGE);
        check("MP4 magic -> VIDEO",  MediaDetector.fromMagicBytes(mp4)  == MediaKind.VIDEO);
        check("MP3 magic -> AUDIO",  MediaDetector.fromMagicBytes(mp3)  == MediaKind.AUDIO);
        check("header image/webp -> IMAGE", MediaDetector.fromContentType("image/webp") == MediaKind.IMAGE);
        check("header image/svg+xml -> SVG", MediaDetector.fromContentType("image/svg+xml") == MediaKind.SVG);
        check("header text/html -> NONE", MediaDetector.fromContentType("text/html; charset=utf-8") == MediaKind.NONE);
        // Type-confusion: PNG bytes served as text/plain still detected via magic.
        check("PNG-as-text/plain still IMAGE", MediaDetector.classify("text/plain", png) == MediaKind.IMAGE);
        // HLS manifest
        check("HLS manifest -> VIDEO", MediaDetector.fromContentType("application/vnd.apple.mpegurl") == MediaKind.VIDEO);

        System.out.println("== Placeholder ==");
        String svg = new String(OrangePlaceholder.svgBytes(MediaKind.IMAGE));
        check("SVG well-formed root", svg.startsWith("<svg") && svg.trim().endsWith("</svg>"));
        check("SVG fills box (100%)", svg.contains("width=\"100%\"") && svg.contains("height=\"100%\""));
        check("SVG orange fill present", svg.contains("#FF6A00"));
        check("data URI is base64 svg", OrangePlaceholder.dataUri(MediaKind.VIDEO).startsWith("data:image/svg+xml;base64,"));
        check("video label present", new String(OrangePlaceholder.svgBytes(MediaKind.VIDEO)).contains("VIDEO HIDDEN"));

        System.out.println("== data: URI rewrite ==");
        String html = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSU\"><p>keep me</p>"
                    + "<video src='data:video/mp4;base64,AAAAAA'></video>";
        String rw = DataUriRewriter.rewrite(html);
        check("original png data-uri removed", !rw.contains("iVBORw0KGgoAAAANSU"));
        check("original mp4 data-uri removed", !rw.contains("data:video/mp4;base64,AAAAAA"));
        check("replaced with svg placeholder", rw.contains("data:image/svg+xml;base64,"));
        check("non-media text preserved", rw.contains("<p>keep me</p>"));
        check("detects media data uri", DataUriRewriter.containsMediaDataUri(html));

        System.out.println("== Metadata extraction (real PNG via ImageIO) ==");
        BufferedImage img = new BufferedImage(320, 240, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(Color.CYAN); g.fillRect(0,0,320,240); g.dispose();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", bos);
        byte[] realPng = bos.toByteArray();
        MediaMetadata m = MetadataExtractor.extract("https://cdn.example/x.png", "GET", (short)200, "image/png", realPng);
        check("dimensions 320x240 read", m.width() == 320 && m.height() == 240);
        check("sha256 present (64 hex)", m.sha256().matches("[0-9a-f]{64}"));
        check("md5 present (32 hex)", m.md5().matches("[0-9a-f]{32}"));
        check("sniffed type PNG", m.sniffedType().equalsIgnoreCase("PNG"));
        check("byte length matches", m.byteLength() == realPng.length);
        check("no false GPS", !m.hasGps());

        System.out.println("== CSV export ==");
        java.util.List<MediaMetadata> rows = java.util.List.of(
            new MediaMetadata("https://x/a,b.jpg", "GET", (short)200, "image/jpeg", "JPEG",
                1234, "abc", "def", 640, 480, true, "51.5, -0.1",
                "Make | Camera = \"Nikon\"\nModel | X = Z6", java.util.List.of("GPS: 51.5, -0.1")),
            new MediaMetadata("=cmd|'/c calc'!A1", "GET", (short)200, "image/png", "PNG",
                9, "h", "m", -1, -1, false, null, "", java.util.List.of())
        );
        String csv = io.splinters.mediashield.export.CsvExporter.toCsv(rows);
        String[] lines = csv.split("\r\n");
        check("CSV has header + 2 rows", lines.length == 3);
        check("header starts with URL", lines[0].startsWith("URL,Method,Status"));
        check("comma-in-url is quoted", lines[1].contains("\"https://x/a,b.jpg\""));
        check("embedded quotes doubled", csv.contains("\"\"Nikon\"\""));
        check("newline field quoted (row not split)", lines.length == 3);
        check("GPS value present", lines[1].contains("51.5, -0.1"));
        check("formula-injection neutralised ('=cmd...)", lines[2].contains("\"'=cmd|'/c calc'!A1\"")
                || lines[2].startsWith("'=cmd"));
        check("CRLF line terminator", csv.contains("\r\n"));

        System.out.println("== WebSocket: format-matched raster ==");
        byte[] jpegRaster = RasterPlaceholder.bytes("jpeg");
        byte[] pngRaster = RasterPlaceholder.bytes("png");
        byte[] webpRaster = RasterPlaceholder.bytes("webp"); // unsupported -> png fallback
        check("jpeg placeholder is really jpeg", MediaDetector.imageFormat(jpegRaster) != null
                && MediaDetector.imageFormat(jpegRaster).equals("jpeg"));
        check("png placeholder is really png", "png".equals(MediaDetector.imageFormat(pngRaster)));
        check("webp falls back to png", "png".equals(MediaDetector.imageFormat(webpRaster)));
        check("jpeg placeholder decodes as image", ImageIO.read(new java.io.ByteArrayInputStream(jpegRaster)) != null);

        System.out.println("== WebSocket: base64-in-JSON ==");
        BufferedImage p = new BufferedImage(48, 48, BufferedImage.TYPE_INT_RGB);
        ByteArrayOutputStream pbos = new ByteArrayOutputStream();
        ImageIO.write(p, "png", pbos);
        String realPngB64 = Base64.getEncoder().encodeToString(pbos.toByteArray());
        String json = "{\"type\":\"image\",\"data\":\"" + realPngB64 + "\",\"caption\":\"hi\"}";
        Base64MediaRewriter.Result b64r = Base64MediaRewriter.rewrite(json);
        check("base64 media replaced", b64r.changed());
        check("original base64 gone", !b64r.text().contains(realPngB64));
        check("surrounding JSON preserved", b64r.text().contains("\"caption\":\"hi\""));
        check("one media extracted for metadata", b64r.extractedMedia().size() == 1);
        // short token must NOT be touched
        Base64MediaRewriter.Result tokenR = Base64MediaRewriter.rewrite("{\"session\":\"YWJjZGVmZ2g\"}");
        check("short token untouched", !tokenR.changed());

        System.out.println("== WebSocket: WsMediaRewriter ==");
        ByteArrayOutputStream jbos = new ByteArrayOutputStream();
        ImageIO.write(new BufferedImage(64,64,BufferedImage.TYPE_INT_RGB), "jpeg", jbos);
        WsMediaRewriter ws = new WsMediaRewriter(ShieldConfig.defaults());
        WsMediaRewriter.BinaryResult br = ws.rewriteBinary(jbos.toByteArray(), "wss://x/ws");
        check("binary frame changed", br.changed());
        check("binary replacement matches source format (jpeg)", "jpeg".equals(MediaDetector.imageFormat(br.payload())));
        check("binary metadata harvested", br.metadata() != null && br.metadata().sniffedType().equalsIgnoreCase("JPEG"));
        WsMediaRewriter.TextResult tr = ws.rewriteText(json, "wss://x/ws");
        check("text frame changed", tr.changed());
        check("text metadata harvested", tr.metadata().size() == 1);
        WsMediaRewriter.BinaryResult noop = ws.rewriteBinary("just plain text frame".getBytes(), "wss://x/ws");
        check("non-media binary unchanged", !noop.changed());

        System.out.printf("%n== RESULT: %d passed, %d failed ==%n", pass, fail);
        if (fail > 0) System.exit(1);
    }
}
