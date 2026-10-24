import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.*;

/** Live network check: DNS lookup, HTTP status, redirects and TLS, using only java.net. */
public class URLscanner {

    @SuppressWarnings("deprecation")
    public static String liveCheck(String raw) {
        StringBuilder sb = new StringBuilder();
        String u = raw.trim();
        if (!u.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) u = "http://" + u;

        HttpURLConnection c = null;
        try {
            URL url = new URL(u);
            String proto = url.getProtocol().toLowerCase();
            if (!proto.equals("http") && !proto.equals("https")) {
                return "Only http:// and https:// links can be checked live.";
            }

            sb.append("Target     : ").append(u).append("\n");

            long t0 = System.currentTimeMillis();
            InetAddress[] addrs = InetAddress.getAllByName(url.getHost());
            sb.append("DNS lookup : OK in ").append(System.currentTimeMillis() - t0).append(" ms -> ");
            for (int i = 0; i < addrs.length && i < 3; i++) {
                sb.append(addrs[i].getHostAddress()).append(i < Math.min(addrs.length, 3) - 1 ? ", " : "");
            }
            sb.append("\n");

            c = (HttpURLConnection) url.openConnection();
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.setRequestMethod("GET");
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (FakeWebsiteDetector)");

            long t1 = System.currentTimeMillis();
            int code = c.getResponseCode();
            sb.append("HTTP       : ").append(code).append(" ").append(c.getResponseMessage())
              .append(" (").append(System.currentTimeMillis() - t1).append(" ms)\n");

            String server = c.getHeaderField("Server");
            if (server != null) sb.append("Server     : ").append(server).append("\n");
            String type = c.getContentType();
            if (type != null) sb.append("Content    : ").append(type).append("\n");

            if (proto.equals("https")) {
                sb.append("TLS        : handshake OK, certificate trusted by Java\n");
            } else {
                sb.append("TLS        : NONE - traffic is not encrypted\n");
            }

            if (code >= 300 && code < 400) {
                String loc = c.getHeaderField("Location");
                if (loc != null) {
                    URL target = new URL(url, loc);
                    sb.append("Redirect   : -> ").append(target).append("\n");
                    if (!target.getHost().equalsIgnoreCase(url.getHost())) {
                        sb.append("WARNING    : redirects to a DIFFERENT host (")
                          .append(target.getHost()).append(")\n");
                    }
                }
            }
        } catch (UnknownHostException e) {
            sb.append("DNS lookup : FAILED - this domain does not exist (dead or fake site)\n");
        } catch (SocketTimeoutException e) {
            sb.append("Result     : TIMED OUT - the server did not answer in 5 seconds\n");
        } catch (SSLException e) {
            sb.append("TLS        : FAILED - invalid or untrusted certificate (")
              .append(e.getMessage()).append(")\n");
        } catch (MalformedURLException e) {
            sb.append("Result     : malformed URL - ").append(e.getMessage()).append("\n");
        } catch (IOException e) {
            sb.append("Result     : connection error - ").append(e.getMessage()).append("\n");
        } finally {
            if (c != null) c.disconnect();
        }
        return sb.toString();
    }
}
