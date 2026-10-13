import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Minimal HTTP/1.1 helpers built on plain sockets only (no com.sun.net.httpserver,
 * no external libraries). Reads one CRLF-terminated line at a time, byte by byte,
 * so the stream is left positioned exactly at the start of whatever follows the
 * header block (important once we start copying raw body bytes off the same socket).
 */
final class HttpUtil {

    private HttpUtil() {}

    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int prev = -1, cur;
        while ((cur = in.read()) != -1) {
            if (prev == '\r' && cur == '\n') {
                byte[] b = line.toByteArray();
                return new String(b, 0, b.length - 1, StandardCharsets.US_ASCII); // drop trailing \r
            }
            line.write(cur);
            prev = cur;
        }
        return line.size() == 0 ? null : line.toString(StandardCharsets.US_ASCII);
    }
}
