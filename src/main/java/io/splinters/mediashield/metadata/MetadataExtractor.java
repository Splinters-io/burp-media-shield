package io.splinters.mediashield.metadata;

import com.drew.imaging.FileType;
import com.drew.imaging.FileTypeDetector;
import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import com.drew.metadata.exif.GpsDirectory;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Extracts metadata from raw media bytes using the drewnoakes metadata-extractor library.
 * Pulls dimensions, EXIF/XMP/IPTC, GPS coordinates and content hashes — all without decoding
 * pixels. Every failure is swallowed into a best-effort result; extraction must never break
 * traffic.
 */
public final class MetadataExtractor {

    private MetadataExtractor() {
    }

    public static MediaMetadata extract(String url,
                                        String method,
                                        short status,
                                        String declaredContentType,
                                        byte[] body) {
        String sniffed = sniff(body);
        String sha256 = hash("SHA-256", body);
        String md5 = hash("MD5", body);

        int width = -1;
        int height = -1;
        boolean hasGps = false;
        String gpsText = null;
        StringBuilder dump = new StringBuilder();
        List<String> notable = new ArrayList<>();

        try {
            Metadata metadata = ImageMetadataReader.readMetadata(new ByteArrayInputStream(body));
            for (Directory dir : metadata.getDirectories()) {
                for (Tag tag : dir.getTags()) {
                    dump.append(dir.getName())
                        .append(" | ")
                        .append(tag.getTagName())
                        .append(" = ")
                        .append(safe(tag.getDescription()))
                        .append('\n');
                }

                int[] wh = readDimensions(dir);
                if (wh != null) {
                    width = wh[0];
                    height = wh[1];
                }

                if (dir instanceof GpsDirectory gps) {
                    var loc = gps.getGeoLocation();
                    if (loc != null && !loc.isZero()) {
                        hasGps = true;
                        gpsText = loc.getLatitude() + ", " + loc.getLongitude();
                        notable.add("GPS: " + gpsText);
                    }
                }
            }
            collectNotable(metadata, notable);
        } catch (Throwable ignored) {
            // Not a parseable image (video/audio/corrupt) — hashes + dimensions may still be null.
        }

        return new MediaMetadata(
                url, method, status, declaredContentType, sniffed,
                body == null ? 0 : body.length, sha256, md5,
                width, height, hasGps, gpsText, dump.toString(), notable);
    }

    private static void collectNotable(Metadata metadata, List<String> notable) {
        addTag(metadata, notable, "Make", "Camera");
        addTag(metadata, notable, "Model", "Model");
        addTag(metadata, notable, "Software", "Software");
        addTag(metadata, notable, "Date/Time Original", "Taken");
        addTag(metadata, notable, "Artist", "Artist");
        addTag(metadata, notable, "Copyright", "Copyright");
        addTag(metadata, notable, "Unique Image ID", "ImageID");
    }

    private static void addTag(Metadata metadata, List<String> out, String tagName, String label) {
        for (Directory dir : metadata.getDirectories()) {
            for (Tag tag : dir.getTags()) {
                if (tag.getTagName().equalsIgnoreCase(tagName)) {
                    String v = safe(tag.getDescription());
                    if (!v.isBlank()) {
                        out.add(label + ": " + v);
                        return;
                    }
                }
            }
        }
    }

    private static int[] readDimensions(Directory dir) {
        Integer w = intTagContaining(dir, "Image Width", "Width");
        Integer h = intTagContaining(dir, "Image Height", "Height");
        if (w != null && h != null && w > 0 && h > 0) {
            return new int[]{w, h};
        }
        return null;
    }

    private static Integer intTagContaining(Directory dir, String... names) {
        for (Tag tag : dir.getTags()) {
            for (String name : names) {
                if (tag.getTagName().equalsIgnoreCase(name)) {
                    try {
                        String d = safe(tag.getDescription()).replaceAll("[^0-9].*$", "").trim();
                        if (!d.isEmpty()) {
                            return Integer.parseInt(d);
                        }
                    } catch (NumberFormatException ignored) {
                        // keep scanning
                    }
                }
            }
        }
        return null;
    }

    private static String sniff(byte[] body) {
        if (body == null || body.length == 0) {
            return "";
        }
        try (var in = new BufferedInputStream(new ByteArrayInputStream(body))) {
            FileType type = FileTypeDetector.detectFileType(in);
            return type == null ? "" : type.name();
        } catch (Throwable t) {
            return "";
        }
    }

    private static String hash(String algorithm, byte[] body) {
        if (body == null) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(body);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
