import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
public class OriginSocketServer {

    static final int BLOCK_SIZE = 1024;

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
