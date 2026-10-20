import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.Executors;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

import java.lang.Thread;

/**
 * Proxy implemented with raw sockets only (java.net.ServerSocket / Socket), no
 * com.sun.net.httpserver, no java.net.http.HttpClient, no external libraries.
 * Serves a small page at "/" and relays GET /video/<file> to the origin server,
 * forwarding the Range header and streaming the response body back block by
 * block (no whole-file buffering). Each browser connection handles one request,
 * then closes.
 *
 * Usage: java ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081]
 */
public class ProxySocketServer {

    static final int BLOCK_SIZE = 1024;

    // Handshake protocol (Phase A: plaintext, no cryptography yet)
    static final int HS_VERSION = 1, HS_RELEASE = 1;
    static final int TYPE_HELLO = 1, TYPE_ACCEPT = 2, TYPE_REQUEST = 3, TYPE_ALERT = 255;
    static final int MAX_PAYLOAD = 64 * 1024;          // reject absurd sizes before allocating
    static final int SRV_BYTES = 32;                   // 256-bit challenge
    static String ALGORITHM; 
    static String MODE;
    static String IV;
    static String PADDING;
    static final SecureRandom RANDOM = new SecureRandom();

    record Message(int type, byte[] payload) {}

    static final String INDEX_HTML = """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>MP4 streamed through a plain-socket proxy</h1>
              <p>File: <input id="f" value="gta6.mp4">
                 <button onclick="load()">Load</button></p>
              <video id="v" controls preload="metadata" style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body></html>
            """;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String originHost = args.length > 1 ? args[1] : "localhost";
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081;

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("Proxy on http://localhost:" + port + "/  ->  http://" + originHost + ":" + originPort);
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, originHost, originPort));
            }
        }
    }

        static void readCryptoSuite(Path configPath) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);

        Element suite = (Element) factory.newDocumentBuilder().parse(configPath.toFile())
                .getElementsByTagName("SymCipherSuite").item(0);
        if (suite == null) throw new IOException("Missing SymCipherSuite in " + configPath);

        String algorithm = suite.getElementsByTagName("Algorithm").item(0).getTextContent().trim();
        String mode = suite.getElementsByTagName("Mode").item(0).getTextContent().trim();
        String padding = suite.getElementsByTagName("Padding").item(0).getTextContent().trim();
        if (algorithm.isEmpty() || mode.isEmpty() || padding.isEmpty())
            throw new IOException("Algorithm, Mode, and Padding must be set in " + configPath);

        ALGORITHM = algorithm;
        MODE = mode;
        PADDING = padding;

    }

    static void handle(Socket browser, String originHost, int originPort) {
        try (browser) {
            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();

            String requestLine = HttpUtil.readLine(in);
            if (requestLine == null || !requestLine.startsWith("GET ")) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }
            String path = requestLine.split(" ")[1];

            String rangeHeader = null;
            String line;
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c > 0 && line.substring(0, c).equalsIgnoreCase("Range")) {
                    rangeHeader = line.substring(c + 1).trim();
                }
            }

            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }
            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }

            String name = path.substring("/video/".length());
            relayFromOrigin(out, originHost, originPort, name, rangeHeader);

        } catch (IOException e) {
            // Browser disconnected or origin unreachable mid-stream: nothing to do.
        }
    }

    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 200 OK\r\n")
                .append("Content-Type: text/html; charset=utf-8\r\n")
                .append("Content-Length: ").append(page.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }

    static void relayFromOrigin(OutputStream browserOut, String originHost, int originPort,
                                 String name, String rangeHeader) throws IOException {
        try (Socket origin = new Socket(originHost, originPort)) {
            OutputStream originOut = origin.getOutputStream();
            InputStream originIn = origin.getInputStream();

            // The server only answers after a successful handshake.
            try {
                handshake(originIn, originOut, name);
            } catch (ProtocolException | EOFException e) {   // we detected the violation: tell the server
                String reason = e instanceof ProtocolException ? e.getMessage() : "truncated message";
                log("handshake failed: " + reason);
                sendAlert(originOut, reason);
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            } catch (ServerAlert e) {                          // the server refused us
                log("server refused: " + e.getMessage());
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            StringBuilder req = new StringBuilder();
            req.append("GET /media/").append(name).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(originHost).append(":").append(originPort).append("\r\n");
            if (rangeHeader != null) req.append("Range: ").append(rangeHeader).append("\r\n");
            req.append("Connection: close\r\n\r\n");
            originOut.write(req.toString().getBytes(StandardCharsets.US_ASCII));
            originOut.flush();

            // Parse the origin's status line + headers
            String statusLine = HttpUtil.readLine(originIn);
            if (statusLine == null) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }
            String[] parts = statusLine.split(" ", 3);
            int code = Integer.parseInt(parts[1]);
            String reason = parts.length > 2 ? parts[2] : "";

            long contentLength = -1;
            String contentType = null, contentRange = null, acceptRanges = null;
            String line;
            while ((line = HttpUtil.readLine(originIn)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c <= 0) continue;
                String h = line.substring(0, c).trim();
                String v = line.substring(c + 1).trim();
                switch (h.toLowerCase()) {
                    case "content-length" -> contentLength = Long.parseLong(v);
                    case "content-type" -> contentType = v;
                    case "content-range" -> contentRange = v;
                    case "accept-ranges" -> acceptRanges = v;
                }
            }

            // Forward status + the headers the browser needs for playback/seeking
            StringBuilder resp = new StringBuilder();
            resp.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n");
            if (contentType != null) resp.append("Content-Type: ").append(contentType).append("\r\n");
            if (acceptRanges != null) resp.append("Accept-Ranges: ").append(acceptRanges).append("\r\n");
            if (contentRange != null) resp.append("Content-Range: ").append(contentRange).append("\r\n");
            if (contentLength >= 0) resp.append("Content-Length: ").append(contentLength).append("\r\n");
            resp.append("Connection: close\r\n\r\n");
            browserOut.write(resp.toString().getBytes(StandardCharsets.US_ASCII));
            browserOut.flush();

            if (contentLength <= 0) return;

            // Relay the body block by block; closing either socket cancels the transfer.
            byte[] buf = new byte[BLOCK_SIZE];
            long remaining = contentLength;
            while (remaining > 0) {
                int n = originIn.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n < 0) break;
		try{
		    Thread.sleep(1);
		    // can you push for the minimum required to
		    // maintain good buffering and playout delay maintaining
		    // a good vizualization-playing experience ?
            // prxy diz quando esta adiantado e muda valor de forma dinamica
		} catch (InterruptedException e) {
		    System.out.println("uppps");
		}
		    
                browserOut.write(buf, 0, n);
                browserOut.flush();
                remaining -= n;
            }
        }
    }

    /** Raised when the server answers with a type-255 alert. */
    static class ServerAlert extends IOException {
        ServerAlert(String reason) { super(reason); }
    }

    /**
     * Proxy side of the 3-message handshake. Returns normally if the server accepted;
     * throws ProtocolException if the server broke the protocol, ServerAlert if it refused.
     *
     *   1  proxy  -> server : SEQX || PCC
     *   2  server -> proxy  : SEQX+1 || SRV || CCC
     *   3  proxy  -> server : SEQX+2 || SHA-256(SRV) || MEDIA_NAME
     */
    static void handshake(InputStream in, OutputStream out, String media) throws IOException {
        // M1: Proxy sends PCC 
        long seqX = RANDOM.nextLong(); // Sequence number starts at a random value to prevent replay attacks.
        ByteArrayOutputStream b1 = new ByteArrayOutputStream();
        DataOutputStream p1 = new DataOutputStream(b1);
        p1.writeLong(seqX);
        p1.writeUTF(ALGORITHM + "/" + MODE + "/" + PADDING);
        writeMessage(out, TYPE_HELLO, b1.toByteArray());

        log(">> 1  SEQX=" + seqX + "  PCC=" + ALGORITHM + "/" + MODE + "/" + PADDING);

        // M2: If Server shares the same cryptographic suite, it accepts and sends challenge  and CCC; otherwise it sends an alert.
        Message m2 = readMessage(in);
        if (m2.type() == TYPE_ALERT) throw new ServerAlert(payloadReader(m2).readUTF());
        if (m2.type() != TYPE_ACCEPT) throw new ProtocolException("Epected Type 2, got Type " + m2.type());

        DataInputStream p2 = payloadReader(m2);
        long seqY = p2.readLong();
        byte[] srv = new byte[SRV_BYTES];
        p2.readFully(srv);
        String ccc = p2.readUTF();

        log("<< 2  SEQY=" + seqY + "  SRV=" + hex(srv).substring(0, 16) + "...  CCC=" + ccc);

        if (seqY != seqX + 1) throw new ProtocolException("Wrong Sequence Number " + seqY + ", expected " + (seqX + 1));

        if (!ccc.equals(ALGORITHM + "/" + MODE + "/" + PADDING)) {
            throw new ProtocolException("Server doesn't support the requested cryptographic suite: " + ccc);
        }

        // M3: Proxy responds to the challenge with SHA-256(SRV) and the requested media name.
        long seqZ = seqY + 1;
        byte[] r = sha256(srv);
        ByteArrayOutputStream b3 = new ByteArrayOutputStream();
        DataOutputStream p3 = new DataOutputStream(b3);
        p3.writeLong(seqZ);
        p3.write(r);
        p3.writeUTF(media);
        writeMessage(out, TYPE_REQUEST, b3.toByteArray());

        log(">> 3  SEQZ=" + seqZ + "  R=" + hex(r).substring(0, 16) + "...  MEDIA=" + media);
    }

    /** Build the whole message first so it leaves in one write (not one TCP segment per field). Plaintext */
    static void writeMessage(OutputStream out, int type, byte[] payload) throws IOException {
        ByteArrayOutputStream msg = new ByteArrayOutputStream(9 + payload.length);
        DataOutputStream d = new DataOutputStream(msg);
        d.writeShort(HS_VERSION);
        d.writeShort(HS_RELEASE);
        d.writeByte(type);
        d.writeInt(payload.length);
        d.write(payload);
        out.write(msg.toByteArray());
        out.flush();
    }

    /** Reads exactly one message: TCP is a byte stream, so the header says how much to read. */
    static Message readMessage(InputStream in) throws IOException {
        DataInputStream d = new DataInputStream(in);
        int version = d.readUnsignedShort();
        int release = d.readUnsignedShort();
        int type = d.readUnsignedByte();
        int size = d.readInt();
        if (version != HS_VERSION || release != HS_RELEASE)
            throw new ProtocolException("unsupported handshake version " + version + ":" + release);
        if (size < 0 || size > MAX_PAYLOAD) throw new ProtocolException("invalid payload size " + size);
        byte[] payload = new byte[size];
        d.readFully(payload);

        return new Message(type, payload);
    }

    static void sendAlert(OutputStream out, String reason) {
        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            new DataOutputStream(b).writeUTF(reason);
            writeMessage(out, TYPE_ALERT, b.toByteArray());
        } catch (IOException ignored) {
            // peer already gone: nothing else to tell it
        }
    }

    static DataInputStream payloadReader(Message m) {
        return new DataInputStream(new ByteArrayInputStream(m.payload()));
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // every JDK ships SHA-256
        }
    }

    /** Used only for logging */
    static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }

    static void log(String s) {
        System.out.println("[proxy] " + s);
    }

    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

}