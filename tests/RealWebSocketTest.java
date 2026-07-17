import io.splinters.mediashield.config.ShieldConfig;
import io.splinters.mediashield.detect.MediaDetector;
import io.splinters.mediashield.rewrite.WsMediaRewriter;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * End-to-end test over a genuine WebSocket: a hand-rolled RFC-6455 server sends a real JPEG
 * (binary frame) and a JSON text frame carrying a base64 PNG; the JDK's real WebSocket client
 * receives them and runs each frame through the shipped WsMediaRewriter, exactly as
 * MediaWebSocketHandler does in Burp. We then decode the blinded output and confirm the pixels
 * are orange.
 */
public class RealWebSocketTest {

    static int pass = 0, fail = 0;
    static void check(String n, boolean c) { System.out.printf("  [%s] %s%n", c ? "PASS" : "FAIL", n); if (c) pass++; else fail++; }

    // ---- real image fixtures (NOT orange, so we can prove the swap happened) ----
    static byte[] blueJpeg() throws Exception {
        BufferedImage img = new BufferedImage(200, 150, BufferedImage.TYPE_INT_RGB);
        var g = img.createGraphics(); g.setColor(new Color(0, 40, 200)); g.fillRect(0,0,200,150); g.dispose();
        ByteArrayOutputStream b = new ByteArrayOutputStream(); ImageIO.write(img, "jpeg", b); return b.toByteArray();
    }
    static byte[] greenPng() throws Exception {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        var g = img.createGraphics(); g.setColor(new Color(0, 180, 0)); g.fillRect(0,0,64,64); g.dispose();
        ByteArrayOutputStream b = new ByteArrayOutputStream(); ImageIO.write(img, "png", b); return b.toByteArray();
    }

    static boolean isOrangeCenter(byte[] imageBytes) throws Exception {
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (img == null) return false;
        Color c = new Color(img.getRGB(img.getWidth()/2, img.getHeight()/2));
        // orange target #FF6A00 (255,106,0), wide tolerance for JPEG re-encode
        return c.getRed() > 200 && c.getGreen() > 50 && c.getGreen() < 160 && c.getBlue() < 90;
    }

    public static void main(String[] args) throws Exception {
        byte[] jpeg = blueJpeg();
        byte[] png = greenPng();
        String json = "{\"type\":\"photo\",\"data\":\"" + Base64.getEncoder().encodeToString(png) + "\",\"user\":\"alice\"}";

        // ---- start a real WebSocket server on an ephemeral port ----
        ServerSocket server = new ServerSocket(0);
        int port = server.getLocalPort();
        Thread serverThread = new Thread(() -> serve(server, jpeg, json));
        serverThread.setDaemon(true);
        serverThread.start();
        System.out.println("Real WebSocket server listening on ws://127.0.0.1:" + port);

        // ---- connect with the JDK's real WebSocket client ----
        WsMediaRewriter shield = new WsMediaRewriter(ShieldConfig.defaults());
        CountDownLatch got = new CountDownLatch(2);
        final byte[][] recvBinary = new byte[1][];
        final String[] recvText = new String[1];

        WebSocket.Listener listener = new WebSocket.Listener() {
            final ByteArrayOutputStream bin = new ByteArrayOutputStream();
            final StringBuilder txt = new StringBuilder();
            @Override public void onOpen(WebSocket ws) { ws.request(1); }
            @Override public CompletionStage<?> onBinary(WebSocket ws, ByteBuffer data, boolean last) {
                byte[] a = new byte[data.remaining()]; data.get(a); bin.writeBytes(a);
                if (last) { recvBinary[0] = bin.toByteArray(); bin.reset(); got.countDown(); }
                ws.request(1); return null;
            }
            @Override public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
                txt.append(data);
                if (last) { recvText[0] = txt.toString(); txt.setLength(0); got.countDown(); }
                ws.request(1); return null;
            }
        };
        WebSocket ws = HttpClient.newHttpClient().newWebSocketBuilder()
                .buildAsync(URI.create("ws://127.0.0.1:" + port + "/media"), listener).join();

        if (!got.await(10, TimeUnit.SECONDS)) { System.out.println("TIMEOUT waiting for frames"); System.exit(1); }

        System.out.println("\n== What arrived over the wire (real WS frames) ==");
        check("binary frame received intact (real JPEG)",
                recvBinary[0] != null && java.util.Arrays.equals(recvBinary[0], jpeg));
        check("received binary is a real image, blue (not orange)",
                MediaDetector.imageFormat(recvBinary[0]) != null && !isOrangeCenter(recvBinary[0]));
        check("text frame received intact (JSON w/ base64 PNG)", json.equals(recvText[0]));

        System.out.println("\n== After the shield processes each frame (as MediaWebSocketHandler would) ==");
        WsMediaRewriter.BinaryResult br = shield.rewriteBinary(recvBinary[0], "ws://127.0.0.1/media");
        check("binary frame blinded (changed)", br.changed());
        check("replacement stays JPEG (format-matched)", "jpeg".equals(MediaDetector.imageFormat(br.payload())));
        check("blinded binary renders ORANGE", isOrangeCenter(br.payload()));
        check("original blue image is gone", !java.util.Arrays.equals(br.payload(), recvBinary[0]));
        check("metadata harvested from original (JPEG, sha256)",
                br.metadata() != null && br.metadata().sha256().matches("[0-9a-f]{64}"));

        WsMediaRewriter.TextResult tr = shield.rewriteText(recvText[0], "ws://127.0.0.1/media");
        check("text frame blinded (changed)", tr.changed());
        check("original base64 PNG removed from JSON",
                !tr.payload().contains(Base64.getEncoder().encodeToString(png)));
        check("surrounding JSON preserved (user:alice)", tr.payload().contains("\"user\":\"alice\""));
        // pull the replacement base64 back out and confirm it decodes to an orange image
        String newB64 = tr.payload().replaceAll(".*\"data\":\"([^\"]+)\".*", "$1");
        byte[] swapped = Base64.getDecoder().decode(newB64);
        check("blinded JSON media renders ORANGE", isOrangeCenter(swapped));

        ws.sendClose(WebSocket.NORMAL_CLOSURE, "done");
        server.close();

        System.out.printf("%n== RESULT: %d passed, %d failed ==%n", pass, fail);
        if (fail > 0) System.exit(1);
    }

    // ---------- minimal RFC-6455 server ----------
    static void serve(ServerSocket server, byte[] jpeg, String json) {
        try (Socket sock = server.accept()) {
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();
            // read handshake headers
            ByteArrayOutputStream hb = new ByteArrayOutputStream();
            int b, state = 0;
            while ((b = in.read()) != -1) {
                hb.write(b);
                state = (b == '\r' && (state==0||state==2)) ? state+1 : (b=='\n' && (state==1||state==3)) ? state+1 : 0;
                if (state == 4) break;
            }
            String req = hb.toString(StandardCharsets.US_ASCII);
            String key = null;
            for (String line : req.split("\r\n")) {
                if (line.toLowerCase().startsWith("sec-websocket-key:")) key = line.substring(line.indexOf(':')+1).trim();
            }
            String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
            out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            // server->client frames are unmasked
            sendFrame(out, 0x2, jpeg);                                   // binary
            sendFrame(out, 0x1, json.getBytes(StandardCharsets.UTF_8));  // text
            out.flush();
            Thread.sleep(500); // let the client drain before we allow close
        } catch (Exception e) {
            System.out.println("server error: " + e);
        }
    }

    static void sendFrame(OutputStream out, int opcode, byte[] payload) throws Exception {
        out.write(0x80 | opcode);
        int len = payload.length;
        if (len < 126) out.write(len);
        else if (len < 65536) { out.write(126); out.write((len>>8)&0xFF); out.write(len&0xFF); }
        else { out.write(127); for (int i=7;i>=0;i--) out.write((int)((long)len>>(8*i))&0xFF); }
        out.write(payload);
    }
}
