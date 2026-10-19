import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.Executors;

/**
 * Origin server implemented with raw sockets only (java.net.ServerSocket / Socket),
 * no com.sun.net.httpserver, no external libraries. Serves files under mediaDir at
 * GET /media/<file>, honouring a single "Range: bytes=start-end" header so seeking
 * works. Each connection handles exactly one request, then closes (Connection: close) -
 * that keeps the hand-written HTTP parsing simple.
 *
 * Usage: java OriginSocketServer [port=8081] [mediaDir=media]
 */
public class StreamServer {

    static final int BLOCK_SIZE = 1024;

    // Handshake protocol (Phase A: plaintext, no cryptography yet)
    static final int HS_VERSION = 1, HS_RELEASE = 1;
    static final int TYPE_HELLO = 1, TYPE_ACCEPT = 2, TYPE_REQUEST = 3, TYPE_ALERT = 255;
    static final int MAX_PAYLOAD = 64 * 1024;          // reject absurd sizes before allocating
    static final int SRV_BYTES = 32;                   // 256-bit challenge
    static final String ACCEPTED_SUITE = "AES/GCM/NoPadding"; // Phase B: read from servercrypto.xml
    static final SecureRandom RANDOM = new SecureRandom();

    record Message(int type, byte[] payload) {}

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8081;
        Path root = Paths.get(args.length > 1 ? args[1] : "media").toAbsolutePath().normalize();

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("Origin server on http://localhost:" + port + "/media/<file.mp4>  (dir: " + root + ")");
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, root));
            }
        }
    }

    static void handle(Socket socket, Path root) {
        try (socket) {
            var in = socket.getInputStream();
            var out = socket.getOutputStream();

            // Nothing is served until the proxy completes the handshake.
            String media;
            try {
                media = handshake(in, out);
            } catch (ProtocolException | EOFException e) {
                String reason = e instanceof ProtocolException ? e.getMessage() : "truncated message";
                log("handshake rejected: " + reason);
                sendAlert(out, reason);
                return;
            }
            log("handshake OK, media=" + media);

            String requestLine = HttpUtil.readLine(in);
            if (requestLine == null || !requestLine.startsWith("GET ")) {
                writeStatus(out, 400, "Bad Request", 0);
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

            if (!path.startsWith("/media/")) {
                writeStatus(out, 404, "Not Found", 0);
                return;
            }
            String name = path.substring("/media/".length());
            if (!name.equals(media)) {          // only the movie agreed in the handshake
                writeStatus(out, 404, "Not Found", 0);
                return;
            }
            Path file = root.resolve(name).normalize();
            if (!file.startsWith(root) || !Files.isRegularFile(file)) {
                writeStatus(out, 404, "Not Found", 0);
                return;
            }

            serveFile(out, file, rangeHeader);
        } catch (IOException e) {
            // Client (the proxy) disconnected mid-stream: normal on seek/close, nothing to do.
        }
    }

    // ------------------------------------------------------------------ handshake

    /**
     * Server side of the 3-message handshake. Returns the requested media name, or throws
     * ProtocolException (the caller answers with a type-255 alert) on any violation.
     *
     *   1  proxy  -> server : SEQX || PCC
     *   2  server -> proxy  : SEQX+1 || SRV || CCC
     *   3  proxy  -> server : SEQX+2 || SHA-256(SRV) || MEDIA
     */
    static String handshake(InputStream in, OutputStream out) throws IOException {
        // Message 1: the proxy's proposal
        Message m1 = readMessage(in);
        if (m1.type() != TYPE_HELLO) throw new ProtocolException("expected type 1, got type " + m1.type());
        DataInputStream p1 = payloadReader(m1);
        long seqX = p1.readLong();
        String pcc = p1.readUTF();
        log("<< 1  SEQX=" + seqX + "  PCC=" + pcc);
        if (!pcc.equals(ACCEPTED_SUITE)) throw new ProtocolException("unsupported suite " + pcc);

        // Message 2: accept + challenge
        long seqY = seqX + 1;
        byte[] srv = new byte[SRV_BYTES];
        RANDOM.nextBytes(srv);
        ByteArrayOutputStream b2 = new ByteArrayOutputStream();
        DataOutputStream p2 = new DataOutputStream(b2);
        p2.writeLong(seqY);
        p2.write(srv);
        p2.writeUTF(ACCEPTED_SUITE);
        writeMessage(out, TYPE_ACCEPT, b2.toByteArray());
        log(">> 2  SEQY=" + seqY + "  SRV=" + hex(srv).substring(0, 16) + "...  CCC=" + ACCEPTED_SUITE);

        // Message 3: challenge response + movie
        Message m3 = readMessage(in);
        if (m3.type() != TYPE_REQUEST) throw new ProtocolException("expected type 3, got type " + m3.type());
        DataInputStream p3 = payloadReader(m3);
        long seqZ = p3.readLong();
        byte[] r = new byte[32];
        p3.readFully(r);
        String media = p3.readUTF();
        log("<< 3  SEQZ=" + seqZ + "  R=" + hex(r).substring(0, 16) + "...  MEDIA=" + media);
        if (seqZ != seqY + 1) throw new ProtocolException("wrong sequence number " + seqZ + ", expected " + (seqY + 1));
        if (!MessageDigest.isEqual(r, sha256(srv))) throw new ProtocolException("wrong challenge response");
        return media;
    }

    /** Header (always plaintext): version(2) | release(2) | type(1) | payload size(4), then the payload. */
    static void writeMessage(OutputStream out, int type, byte[] payload) throws IOException {
        // Build the whole message first so it leaves in one write (not one TCP segment per field).
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

    static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }

    static void log(String s) {
        System.out.println("[server] " + s);
    }

    // ------------------------------------------------------------------ media

    static void serveFile(OutputStream out, Path file, String rangeHeader) throws IOException {
        long size = Files.size(file);
        long start = 0, end = size - 1;
        boolean partial = false;

        if (rangeHeader != null && rangeHeader.startsWith("bytes=") && !rangeHeader.contains(",")) {
            try {
                String[] p = rangeHeader.substring(6).trim().split("-", -1);
                long s, e = end;
                if (p[0].isEmpty()) {
                    s = Math.max(0, size - Long.parseLong(p[1]));
                } else {
                    s = Long.parseLong(p[0]);
                    if (p.length > 1 && !p[1].isEmpty()) e = Math.min(Long.parseLong(p[1]), size - 1);
                }
                if (s > e || s >= size) {
                    writeHeaders(out, 416, "Range Not Satisfiable", 0, null,
                            "Content-Range: bytes */" + size + "\r\n");
                    return;
                }
                start = s;
                end = e;
                partial = true;
            } catch (NumberFormatException | ArrayIndexOutOfBoundsException ignored) {
                // Malformed Range -> fall through and serve the whole file
            }
        }

        long length = end - start + 1;
        String extraHeaders = "Accept-Ranges: bytes\r\n" +
                (partial ? "Content-Range: bytes " + start + "-" + end + "/" + size + "\r\n" : "");
        writeHeaders(out, partial ? 206 : 200, partial ? "Partial Content" : "OK", length, "video/mp4", extraHeaders);

        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            raf.seek(start);
            byte[] block = new byte[BLOCK_SIZE];
            long remaining = length;
            while (remaining > 0) {
                int n = raf.read(block, 0, (int) Math.min(block.length, remaining));
                if (n < 0) break;
                out.write(block, 0, n);
                out.flush();
                remaining -= n;
            }
        }
    }

    static void writeStatus(OutputStream out, int code, String reason, long contentLength) throws IOException {
        writeHeaders(out, code, reason, contentLength, null, null);
    }

    static void writeHeaders(OutputStream out, int code, String reason, long contentLength,
                              String contentType, String extraHeaders) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n");
        if (contentType != null) sb.append("Content-Type: ").append(contentType).append("\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Connection: close\r\n");
        if (extraHeaders != null) sb.append(extraHeaders);
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}