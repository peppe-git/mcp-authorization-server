// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The fetcher against a real TLS server on the loopback interface. The address policy is the real one:
 * the resolver answers with addresses chosen by each test, and the connector sends the connection to the
 * local server while recording which address the fetcher wanted to reach.
 */
class MetadataDocumentFetcherTest {

	static final String DOC = "{\"client_id\":\"https://cimd.test/client.json\",\"redirect_uris\":[\"https://cimd.test/cb\"]}";

	static final URI URL = URI.create("https://cimd.test/client.json");

	/** A public address that is never contacted: the test connector redirects to the local server. */
	static final String PUBLIC = "93.184.216.34";

	private final List<InetAddress> connected = new CopyOnWriteArrayList<>();

	@Test
	void fetchesAValidDocumentAndReadsCacheControl() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK",
				"Content-Type: application/json; charset=utf-8\r\nCache-Control: public, max-age=600\r\nContent-Length: "
						+ DOC.length(), DOC))) {
			MetadataDocumentFetcher.Document doc = fetcher(server, PUBLIC).fetch(URL);
			assertThat(new String(doc.body(), StandardCharsets.UTF_8)).isEqualTo(DOC);
			assertThat(doc.maxAge()).isEqualTo(Duration.ofSeconds(600));
			assertThat(this.connected).containsExactly(InetAddress.getByName(PUBLIC));
			assertThat(server.requests().get(0)).startsWith("GET /client.json HTTP/1.1\r\n").contains("Host: cimd.test\r\n");
		}
	}

	@Test
	void readsAChunkedBody() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> {
			out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
					+ Integer.toHexString(10) + "\r\n" + DOC.substring(0, 10) + "\r\n"
					+ Integer.toHexString(DOC.length() - 10) + "\r\n" + DOC.substring(10) + "\r\n0\r\n\r\n")
				.getBytes(StandardCharsets.US_ASCII));
		})) {
			assertThat(new String(fetcher(server, PUBLIC).fetch(URL).body(), StandardCharsets.UTF_8)).isEqualTo(DOC);
		}
	}

	@Test
	void aPrivateAddressIsRejectedWithoutConnecting() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK", json(DOC), DOC))) {
			for (String internal : new String[] { "127.0.0.1", "10.0.0.5", "169.254.169.254", "100.100.1.1", "::1",
					"fd00::1", "64:ff9b::a00:1", "2002:a00:1::1", "::ffff:0:a00:1" }) {
				assertThatThrownBy(() -> fetcher(server, internal).fetch(URL)).as(internal)
					.isInstanceOf(ClientMetadataException.class)
					.hasMessageContaining("non-public");
			}
			assertThat(this.connected).isEmpty();
			assertThat(server.requests()).isEmpty();
		}
	}

	@Test
	void oneInternalAddressAmongPublicOnesRejectsTheHost() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK", json(DOC), DOC))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC, "127.0.0.1").fetch(URL))
				.isInstanceOf(ClientMetadataException.class);
			assertThat(this.connected).isEmpty();
		}
	}

	@Test
	void dnsRebindingCannotSwapTheAddressAfterTheCheck() throws Exception {
		AtomicInteger lookups = new AtomicInteger();
		HostResolver rebinding = host -> new InetAddress[] {
				InetAddress.getByName(lookups.getAndIncrement() == 0 ? PUBLIC : "127.0.0.1") };
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK", json(DOC), DOC))) {
			MetadataDocumentFetcher f = new MetadataDocumentFetcher(rebinding, AddressPolicy::isAllowed,
					server.connector(this.connected), TestTls.clientFactory(), Duration.ofSeconds(5), 5120);
			f.fetch(URL);
			// One resolution only, and the connection went to the address that passed the check.
			assertThat(lookups.get()).isEqualTo(1);
			assertThat(this.connected).containsExactly(InetAddress.getByName(PUBLIC));
		}
	}

	@Test
	void tooLargeByContentLengthIsRejectedBeforeReading() throws Exception {
		try (TestTls.Server server = new TestTls.Server(
				(head, out) -> respond(out, "200 OK", "Content-Type: application/json\r\nContent-Length: 10000", "{}"))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).hasMessageContaining("larger than 5120");
		}
	}

	@Test
	void tooLargeWithoutLengthIsRejectedAtTheLimit() throws Exception {
		String big = "{\"x\":\"" + "a".repeat(6000) + "\"}";
		try (TestTls.Server server = new TestTls.Server(
				(head, out) -> respond(out, "200 OK", "Content-Type: application/json\r\nConnection: close", big))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).hasMessageContaining("larger than 5120");
		}
		try (TestTls.Server server = new TestTls.Server((head, out) -> out.write(
				("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + "1770\r\n"
						+ big.substring(0, 6000) + "\r\n0\r\n\r\n")
					.getBytes(StandardCharsets.US_ASCII)))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).hasMessageContaining("larger than 5120");
		}
	}

	@Test
	void aSlowBodyHitsTheTotalDeadline() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> {
			out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
				.getBytes(StandardCharsets.US_ASCII));
			out.flush();
			for (int i = 0; i < 100; i++) {
				Thread.sleep(200);
				out.write('x');
				out.flush();
			}
		})) {
			long start = System.nanoTime();
			assertThatThrownBy(() -> fetcher(server, PUBLIC, Duration.ofSeconds(1)).fetch(URL))
				.hasMessageContaining("timed out");
			assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(2500));
		}
	}

	@Test
	void aServerThatNeverAnswersHitsTheDeadline() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> Thread.sleep(10_000))) {
			long start = System.nanoTime();
			assertThatThrownBy(() -> fetcher(server, PUBLIC, Duration.ofSeconds(1)).fetch(URL))
				.hasMessageContaining("timed out");
			assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(2500));
		}
		// A peer that accepts TCP but never starts TLS.
		try (TestTls.Server server = new TestTls.Server((head, out) -> Thread.sleep(10_000), false)) {
			long start = System.nanoTime();
			assertThatThrownBy(() -> fetcher(server, PUBLIC, Duration.ofSeconds(1)).fetch(URL))
				.hasMessageContaining("timed out");
			assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(2500));
		}
	}

	@Test
	void redirectsAreNotFollowed() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "302 Found",
				"Location: https://169.254.169.254/latest/meta-data\r\nContent-Length: 0", ""))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).hasMessageContaining("redirects are not followed");
			assertThat(server.requests()).hasSize(1);
		}
	}

	@Test
	void statusMediaTypeEncodingAndFramingAreChecked() throws Exception {
		String[][] cases = { { "404 Not Found", json(DOC) }, { "200 OK", "Content-Type: text/html\r\nContent-Length: 2" },
				{ "200 OK", "Content-Length: 2" },
				{ "200 OK", "Content-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2" },
				{ "200 OK", "Content-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3" },
				{ "200 OK", "Content-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked" },
				{ "200 OK", "Content-Type: application/json\r\n folded: header\r\nContent-Length: 2" } };
		for (String[] c : cases) {
			try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, c[0], c[1], "{}"))) {
				assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).as(c[0] + " / " + c[1])
					.isInstanceOf(ClientMetadataException.class);
			}
		}
	}

	@Test
	void anOversizedResponseHeadIsRejected() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK",
				"Content-Type: application/json\r\nX-Padding: " + "a".repeat(9000) + "\r\nContent-Length: 2", "{}"))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URL)).hasMessageContaining("response head larger");
		}
	}

	@Test
	void theCertificateMustMatchTheHostName() throws Exception {
		try (TestTls.Server server = new TestTls.Server((head, out) -> respond(out, "200 OK", json(DOC), DOC))) {
			assertThatThrownBy(() -> fetcher(server, PUBLIC).fetch(URI.create("https://evil.test/client.json")))
				.isInstanceOf(ClientMetadataException.class)
				.hasMessageContaining("fetch failed");
			assertThat(server.requests()).isEmpty();
		}
	}

	@Test
	void anUnresolvableHostIsRejected() throws Exception {
		MetadataDocumentFetcher f = new MetadataDocumentFetcher(host -> {
			throw new java.net.UnknownHostException(host);
		}, AddressPolicy::isAllowed, (a, p, t) -> {
			throw new AssertionError("must not connect");
		}, TestTls.clientFactory(), Duration.ofSeconds(1), 5120);
		assertThatThrownBy(() -> f.fetch(URL)).hasMessageContaining("does not resolve");
	}

	private MetadataDocumentFetcher fetcher(TestTls.Server server, String... addresses) throws Exception {
		return fetcher(server, Duration.ofSeconds(5), addresses);
	}

	private MetadataDocumentFetcher fetcher(TestTls.Server server, String address, Duration timeout) throws Exception {
		return fetcher(server, timeout, address);
	}

	private MetadataDocumentFetcher fetcher(TestTls.Server server, Duration timeout, String... addresses)
			throws Exception {
		InetAddress[] resolved = new InetAddress[addresses.length];
		for (int i = 0; i < addresses.length; i++) {
			resolved[i] = InetAddress.getByName(addresses[i]);
		}
		return new MetadataDocumentFetcher(host -> resolved, AddressPolicy::isAllowed, server.connector(this.connected),
				TestTls.clientFactory(), timeout, 5120);
	}

	private static String json(String body) {
		return "Content-Type: application/json\r\nContent-Length: " + body.length();
	}

	private static void respond(OutputStream out, String status, String headers, String body) throws Exception {
		out.write(("HTTP/1.1 " + status + "\r\n" + headers + "\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8));
		out.flush();
	}

}
