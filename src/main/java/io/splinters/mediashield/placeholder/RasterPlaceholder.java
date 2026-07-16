package io.splinters.mediashield.placeholder;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Generates a bright-orange raster (real PNG/JPEG/GIF/BMP bytes) for contexts where we cannot
 * control a Content-Type — chiefly WebSocket frames, where the page's JavaScript decides how to
 * decode the bytes. Substituting a real image in the SAME format the app expects makes the app
 * render orange instead of a broken image.
 *
 * <p>Encoded results are cached per format. Formats Java's ImageIO cannot encode (webp/heic/avif)
 * fall back to PNG — the app may then show a broken image, which is still fully blinded.
 */
public final class RasterPlaceholder {

    private static final String ORANGE = "FF6A00";
    private static final int W = 400;
    private static final int H = 300;

    private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();

    private RasterPlaceholder() {
    }

    /** Orange raster bytes in {@code format} (png/jpeg/gif/bmp); unknown/unsupported → PNG. */
    public static byte[] bytes(String format) {
        String fmt = normalise(format);
        return CACHE.computeIfAbsent(fmt, RasterPlaceholder::encode);
    }

    /** Base64 of {@link #bytes(String)}, for embedding back into a text frame / JSON field. */
    public static String base64(String format) {
        return Base64.getEncoder().encodeToString(bytes(format));
    }

    private static String normalise(String format) {
        if (format == null) {
            return "png";
        }
        String f = format.toLowerCase();
        return switch (f) {
            case "jpg", "jpeg" -> "jpeg";
            case "png", "gif", "bmp" -> f;
            default -> "png"; // webp/heic/avif/tiff/ico -> PNG fallback (ImageIO can't encode them)
        };
    }

    private static byte[] encode(String format) {
        // GIF/BMP/JPEG have no usable alpha; use an opaque image for all so colours stay true.
        BufferedImage img = new BufferedImage(W, H, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color orange = new Color(Integer.parseInt(ORANGE, 16));
            g.setColor(orange);
            g.fillRect(0, 0, W, H);
            g.setColor(new Color(0x1A1200));
            g.setStroke(new java.awt.BasicStroke(6f));
            g.drawRect(6, 6, W - 12, H - 12);
            g.setFont(new Font(Font.MONOSPACED, Font.BOLD, 26));
            String label = "MEDIA HIDDEN";
            int tw = g.getFontMetrics().stringWidth(label);
            g.drawString(label, (W - tw) / 2, H / 2 + 9);
        } finally {
            g.dispose();
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            boolean ok = ImageIO.write(img, format, out);
            if (!ok) {
                ByteArrayOutputStream pngOut = new ByteArrayOutputStream();
                ImageIO.write(img, "png", pngOut);
                return pngOut.toByteArray();
            }
            return out.toByteArray();
        } catch (Exception e) {
            // Last-ditch: a 1x1 orange PNG is better than throwing on the WS path.
            return MINIMAL_PNG;
        }
    }

    // A tiny valid PNG (1x1) as an absolute fallback so the handler never fails.
    private static final byte[] MINIMAL_PNG = Base64.getDecoder().decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");
}
