package io.splinters.mediashield.rewrite;

import io.splinters.mediashield.detect.MediaKind;
import io.splinters.mediashield.placeholder.OrangePlaceholder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Neutralises inline media inside HTML bodies that would NOT arrive as their own HTTP response:
 * <ul>
 *   <li>{@code data:} media URIs (via {@link DataUriRewriter})</li>
 *   <li>inline {@code <svg>} vector art — raster {@code <image>} refs blanked to the placeholder</li>
 *   <li>{@code poster=} frames on {@code <video>} (a still that would otherwise flash before play)</li>
 * </ul>
 *
 * <p>Media referenced by remote/relative URL ({@code <img src="/a.jpg">}, CSS backgrounds, HLS
 * segments, ...) is deliberately left alone here — the browser fetches each as a separate
 * response that the Content-Type swap already blinds. Regex on HTML is imperfect by nature; this
 * layer is belt-and-braces over that primary defence, not the primary defence itself.
 */
public final class HtmlMediaRewriter {

    private static final Pattern POSTER_ATTR = Pattern.compile(
            "(\\bposter\\s*=\\s*)([\"'])(.*?)\\2", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // href / xlink:href on an <image> element inside inline SVG.
    private static final Pattern SVG_IMAGE_HREF = Pattern.compile(
            "(<image\\b[^>]*?\\b(?:xlink:href|href)\\s*=\\s*)([\"'])(.*?)\\2",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private HtmlMediaRewriter() {
    }

    public static String rewrite(String html) {
        if (html == null || html.isEmpty()) {
            return html;
        }
        String out = DataUriRewriter.rewrite(html);
        out = blankPoster(out);
        out = blankSvgImages(out);
        return out;
    }

    private static String blankPoster(String html) {
        Matcher m = POSTER_ATTR.matcher(html);
        String replacement = OrangePlaceholder.dataUri(MediaKind.VIDEO);
        StringBuilder sb = new StringBuilder(html.length());
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(
                    m.group(1) + m.group(2) + replacement + m.group(2)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String blankSvgImages(String html) {
        Matcher m = SVG_IMAGE_HREF.matcher(html);
        String replacement = OrangePlaceholder.dataUri(MediaKind.IMAGE);
        StringBuilder sb = new StringBuilder(html.length());
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(
                    m.group(1) + m.group(2) + replacement + m.group(2)));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
