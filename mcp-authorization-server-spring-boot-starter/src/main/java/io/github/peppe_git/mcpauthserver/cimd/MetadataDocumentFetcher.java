// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Downloads a Client ID Metadata Document without letting the URL reach anything but a public host
 * (ADR-0002).
 *
 * <ol>
 * <li>The host is resolved <b>once</b>, every returned address must pass the address policy, and the
 * connection goes to one of those very addresses: there is no second resolution for a rebinding
 * resolver to poison.</li>
 * <li>TLS uses the original host name for SNI and RFC 2818 host name verification.</li>
 * <li>One total deadline covers connect, handshake, request and the whole body: a watchdog closes the
 * socket when it expires, and every read gets the remaining time as socket timeout.</li>
 * <li>Status must be 200 (redirects are never followed), the media type JSON, the header block at most
 * 8 KiB and the body at most {@code maxBodyBytes}, however it is framed.</li>
 * </ol>
 * The HTTP/1.1 subset spoken here reads exactly one response from an untrusted server; its job is to
 * bound and to reject, not to be complete.
 */
public final class MetadataDocumentFetcher {

	/** A downloaded document and the caching information its response carried. */
	public record Document(byte[] body, Duration maxAge, boolean noStore) {
	}

	static final int MAX_HEADER_BYTES = 8 * 1024;

	private static final Pattern TOKEN = Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");

	private static final Pattern JSON_MEDIA_TYPE = Pattern.compile("^application/([a-z0-9.+-]+\\+)?json$");

	private static final Pattern IPV4_LITERAL = Pattern.compile("^[0-9.]+$");

	private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "mcp-cimd-fetch-watchdog");
		t.setDaemon(true);
		return t;
	});

	private final HostResolver resolver;

	private final Predicate<InetAddress> addressPolicy;

	private final SocketConnector connector;

	private final SSLSocketFactory sslSocketFactory;

	private final Duration timeout;

	private final int maxBodyBytes;

	/** A fetcher with the system resolver, the public-address policy and the default trust store. */
	public MetadataDocumentFetcher(Duration timeout, int maxBodyBytes) {
		this(HostResolver.system(), AddressPolicy::isAllowed, SocketConnector.direct(),
				(SSLSocketFactory) SSLSocketFactory.getDefault(), timeout, maxBodyBytes);
	}

	/** Full constructor; package-private so that only tests can relax the address policy. */
	MetadataDocumentFetcher(HostResolver resolver, Predicate<InetAddress> addressPolicy, SocketConnector connector,
			SSLSocketFactory sslSocketFactory, Duration timeout, int maxBodyBytes) {
		if (timeout.isNegative() || timeout.isZero()) {
			throw new IllegalArgumentException("timeout must be positive");
		}
		if (maxBodyBytes < 256 || maxBodyBytes > 64 * 1024) {
			throw new IllegalArgumentException("maxBodyBytes must be between 256 and 65536");
		}
		this.resolver = resolver;
		this.addressPolicy = addressPolicy;
		this.connector = connector;
		this.sslSocketFactory = sslSocketFactory;
		this.timeout = timeout;
		this.maxBodyBytes = maxBodyBytes;
	}

	/** Fetches {@code uri}, which must already have passed {@link ClientIdUrls#validate}. */
	public Document fetch(URI uri) throws ClientMetadataException {
		long deadline = System.nanoTime() + this.timeout.toNanos();
		String uriHost = uri.getHost();
		boolean ipv6Literal = uriHost.startsWith("[");
		String host = ipv6Literal ? uriHost.substring(1, uriHost.length() - 1) : uriHost;
		int port = (uri.getPort() == -1) ? 443 : uri.getPort();

		InetAddress[] addresses;
		try {
			addresses = this.resolver.resolve(host);
		}
		catch (UnknownHostException ex) {
			throw new ClientMetadataException("host does not resolve");
		}
		if (addresses == null || addresses.length == 0) {
			throw new ClientMetadataException("host does not resolve");
		}
		for (InetAddress address : addresses) {
			if (address == null || !this.addressPolicy.test(address)) {
				throw new ClientMetadataException("host resolves to a non-public address");
			}
		}

		IOException lastConnectFailure = null;
		for (InetAddress address : addresses) {
			Socket plain;
			try {
				plain = this.connector.connect(address, port, remainingMillis(deadline));
			}
			catch (IOException ex) {
				lastConnectFailure = ex;
				if (remainingNanos(deadline) <= 0) {
					break;
				}
				continue;
			}
			ScheduledFuture<?> watchdog = WATCHDOG.schedule(() -> closeQuietly(plain), remainingNanos(deadline),
					TimeUnit.NANOSECONDS);
			try {
				SSLSocket tls = handshake(plain, host, port, ipv6Literal || IPV4_LITERAL.matcher(host).matches(),
						deadline);
				try (tls) {
					return exchange(tls, uri, uriHost, port, deadline);
				}
			}
			catch (IOException ex) {
				if (remainingNanos(deadline) <= 0 || ex instanceof SocketTimeoutException) {
					throw new ClientMetadataException("fetch timed out");
				}
				throw new ClientMetadataException("fetch failed: " + ex.getClass().getSimpleName());
			}
			finally {
				watchdog.cancel(false);
				closeQuietly(plain);
			}
		}
		if (remainingNanos(deadline) <= 0) {
			throw new ClientMetadataException("fetch timed out");
		}
		throw new ClientMetadataException("connection failed"
				+ (lastConnectFailure == null ? "" : ": " + lastConnectFailure.getClass().getSimpleName()));
	}

	private SSLSocket handshake(Socket plain, String host, int port, boolean ipLiteral, long deadline)
			throws IOException {
		SSLSocket tls = (SSLSocket) this.sslSocketFactory.createSocket(plain, host, port, true);
		SSLParameters params = tls.getSSLParameters();
		params.setEndpointIdentificationAlgorithm("HTTPS");
		if (!ipLiteral) {
			try {
				params.setServerNames(List.of(new SNIHostName(host)));
			}
			catch (IllegalArgumentException ex) {
				throw new IOException("host name not usable for TLS");
			}
		}
		tls.setSSLParameters(params);
		tls.setSoTimeout(remainingMillis(deadline));
		tls.startHandshake();
		return tls;
	}

	private Document exchange(SSLSocket tls, URI uri, String uriHost, int port, long deadline)
			throws IOException, ClientMetadataException {
		String target = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
		String hostHeader = uriHost + (port == 443 ? "" : ":" + port);
		String request = "GET " + target + " HTTP/1.1\r\n" + "Host: " + hostHeader + "\r\n"
				+ "Accept: application/json\r\n" + "Accept-Encoding: identity\r\n"
				+ "User-Agent: mcp-authorization-server\r\n" + "Connection: close\r\n\r\n";
		if (!StandardCharsets.US_ASCII.newEncoder().canEncode(request)) {
			throw new ClientMetadataException("client_id contains characters that are not URL-encoded");
		}
		OutputStream out = tls.getOutputStream();
		out.write(request.getBytes(StandardCharsets.US_ASCII));
		out.flush();
		InputStream in = new BufferedInputStream(new DeadlineInputStream(tls, deadline), 1024);
		return readResponse(in);
	}

	private Document readResponse(InputStream in) throws IOException, ClientMetadataException {
		int[] headerBudget = { MAX_HEADER_BYTES };
		String statusLine = readLine(in, headerBudget);
		String[] parts = statusLine.split(" ", 3);
		if (parts.length < 2 || !(parts[0].equals("HTTP/1.1") || parts[0].equals("HTTP/1.0"))
				|| !parts[1].matches("\\d{3}")) {
			throw new ClientMetadataException("malformed HTTP status line");
		}
		int status = Integer.parseInt(parts[1]);
		if (status != 200) {
			throw new ClientMetadataException("HTTP status " + status
					+ ((status >= 300 && status < 400) ? " (redirects are not followed)" : ""));
		}
		Map<String, List<String>> headers = new HashMap<>();
		while (true) {
			String line = readLine(in, headerBudget);
			if (line.isEmpty()) {
				break;
			}
			if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
				throw new ClientMetadataException("folded header lines are not accepted");
			}
			int colon = line.indexOf(':');
			if (colon <= 0 || !TOKEN.matcher(line.substring(0, colon)).matches()) {
				throw new ClientMetadataException("malformed header line");
			}
			headers.computeIfAbsent(line.substring(0, colon).toLowerCase(Locale.ROOT), k -> new ArrayList<>())
				.add(line.substring(colon + 1).strip());
		}

		String encoding = single(headers, "content-encoding");
		if (encoding != null && !encoding.equalsIgnoreCase("identity")) {
			throw new ClientMetadataException("content encoding " + encoding + " is not accepted");
		}
		String contentType = single(headers, "content-type");
		String mediaType = (contentType == null) ? ""
				: contentType.split(";", 2)[0].strip().toLowerCase(Locale.ROOT);
		if (!JSON_MEDIA_TYPE.matcher(mediaType).matches()) {
			throw new ClientMetadataException("media type is not JSON");
		}
		String transferEncoding = single(headers, "transfer-encoding");
		List<String> lengths = headers.get("content-length");
		if (transferEncoding != null && lengths != null) {
			throw new ClientMetadataException("both Transfer-Encoding and Content-Length are present");
		}

		byte[] body;
		if (transferEncoding != null) {
			if (!transferEncoding.equalsIgnoreCase("chunked")) {
				throw new ClientMetadataException("transfer encoding " + transferEncoding + " is not accepted");
			}
			body = readChunked(in);
		}
		else if (lengths != null) {
			long length = contentLength(lengths);
			if (length > this.maxBodyBytes) {
				throw tooLarge();
			}
			body = in.readNBytes((int) length);
			if (body.length != length) {
				throw new ClientMetadataException("body shorter than Content-Length");
			}
		}
		else {
			body = in.readNBytes(this.maxBodyBytes + 1);
			if (body.length > this.maxBodyBytes) {
				throw tooLarge();
			}
		}
		return cacheInfo(body, headers.get("cache-control"));
	}

	private byte[] readChunked(InputStream in) throws IOException, ClientMetadataException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int[] lineBudget = { MAX_HEADER_BYTES };
		while (true) {
			String sizeLine = readLine(in, lineBudget).split(";", 2)[0].strip();
			if (!sizeLine.matches("[0-9a-fA-F]{1,8}")) {
				throw new ClientMetadataException("malformed chunk size");
			}
			long size = Long.parseLong(sizeLine, 16);
			if (size == 0) {
				while (!readLine(in, lineBudget).isEmpty()) {
					// trailer fields are read and ignored, within the header budget
				}
				return out.toByteArray();
			}
			if (out.size() + size > this.maxBodyBytes) {
				throw tooLarge();
			}
			byte[] chunk = in.readNBytes((int) size);
			if (chunk.length != size) {
				throw new ClientMetadataException("truncated chunk");
			}
			out.write(chunk);
			if (!readLine(in, lineBudget).isEmpty()) {
				throw new ClientMetadataException("malformed chunk terminator");
			}
		}
	}

	private Document cacheInfo(byte[] body, List<String> cacheControl) {
		Duration maxAge = null;
		boolean noStore = false;
		if (cacheControl != null) {
			for (String value : cacheControl) {
				for (String directive : value.split(",")) {
					String d = directive.strip().toLowerCase(Locale.ROOT);
					if (d.equals("no-store") || d.equals("no-cache")) {
						noStore = true;
					}
					else if (d.startsWith("max-age=")) {
						String n = d.substring("max-age=".length()).replace("\"", "");
						if (n.matches("\\d{1,9}")) {
							maxAge = Duration.ofSeconds(Long.parseLong(n));
						}
					}
				}
			}
		}
		return new Document(body, maxAge, noStore);
	}

	private ClientMetadataException tooLarge() {
		return new ClientMetadataException("document larger than " + this.maxBodyBytes + " bytes");
	}

	private static long contentLength(List<String> values) throws ClientMetadataException {
		String first = null;
		for (String v : values) {
			for (String part : v.split(",")) {
				String p = part.strip();
				if (!p.matches("\\d{1,10}")) {
					throw new ClientMetadataException("malformed Content-Length");
				}
				if (first != null && !first.equals(p)) {
					throw new ClientMetadataException("conflicting Content-Length values");
				}
				first = p;
			}
		}
		return Long.parseLong(first);
	}

	private static String single(Map<String, List<String>> headers, String name) throws ClientMetadataException {
		List<String> values = headers.get(name);
		if (values == null) {
			return null;
		}
		if (values.size() != 1) {
			throw new ClientMetadataException("repeated " + name + " header");
		}
		return values.get(0);
	}

	/** Reads one line (CRLF or LF), charging its bytes to {@code budget[0]}. */
	private static String readLine(InputStream in, int[] budget) throws IOException, ClientMetadataException {
		ByteArrayOutputStream line = new ByteArrayOutputStream(64);
		while (true) {
			int b = in.read();
			if (b == -1) {
				throw new ClientMetadataException("connection closed in the middle of the response head");
			}
			if (--budget[0] < 0) {
				throw new ClientMetadataException("response head larger than " + MAX_HEADER_BYTES + " bytes");
			}
			if (b == '\n') {
				byte[] bytes = line.toByteArray();
				int len = (bytes.length > 0 && bytes[bytes.length - 1] == '\r') ? bytes.length - 1 : bytes.length;
				for (int i = 0; i < len; i++) {
					if ((bytes[i] >= 0 && bytes[i] < 0x20 && bytes[i] != '\t') || bytes[i] == 0x7f) {
						throw new ClientMetadataException("control character in the response head");
					}
				}
				return new String(bytes, 0, len, StandardCharsets.ISO_8859_1);
			}
			line.write(b);
		}
	}

	private static long remainingNanos(long deadline) {
		return deadline - System.nanoTime();
	}

	private static int remainingMillis(long deadline) throws SocketTimeoutException {
		long nanos = remainingNanos(deadline);
		if (nanos <= 0) {
			throw new SocketTimeoutException("deadline expired");
		}
		return (int) Math.max(1, Math.min(Integer.MAX_VALUE, TimeUnit.NANOSECONDS.toMillis(nanos)));
	}

	private static void closeQuietly(Socket socket) {
		try {
			socket.close();
		}
		catch (IOException ex) {
			// nothing to do: the socket is unusable either way
		}
	}

	/** Gives every read the time left before the deadline, and fails once it has passed. */
	private static final class DeadlineInputStream extends InputStream {

		private final Socket socket;

		private final InputStream delegate;

		private final long deadline;

		DeadlineInputStream(Socket socket, long deadline) throws IOException {
			this.socket = socket;
			this.delegate = socket.getInputStream();
			this.deadline = deadline;
		}

		@Override
		public int read() throws IOException {
			byte[] one = new byte[1];
			int n = read(one, 0, 1);
			return (n == -1) ? -1 : one[0] & 0xff;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			this.socket.setSoTimeout(remainingMillis(this.deadline));
			return this.delegate.read(b, off, len);
		}

	}

}
