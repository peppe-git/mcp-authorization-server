// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Test support: a throw-away certificate for {@code cimd.test} made with the JDK's keytool, a TLS server
 * on the loopback interface driven by a script, and a connector that sends every connection to it while
 * recording the address the fetcher asked for.
 */
public final class TestTls {

	public static final String HOST = "cimd.test";

	private static SSLContext context;

	private TestTls() {
	}

	public static synchronized SSLContext context() throws Exception {
		if (context == null) {
			Path dir = Files.createTempDirectory("mcp-tls");
			Path store = dir.resolve("test.p12");
			Process p = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
					"-genkeypair", "-alias", "test", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + HOST,
					"-ext", "SAN=dns:" + HOST, "-validity", "2", "-storetype", "PKCS12", "-keystore", store.toString(),
					"-storepass", "changeit", "-keypass", "changeit")
				.redirectErrorStream(true)
				.start();
			p.getInputStream().readAllBytes();
			if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
				throw new IllegalStateException("keytool failed");
			}
			KeyStore ks = KeyStore.getInstance("PKCS12");
			try (FileInputStream in = new FileInputStream(store.toFile())) {
				ks.load(in, "changeit".toCharArray());
			}
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, "changeit".toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			context = ctx;
		}
		return context;
	}

	public static SSLSocketFactory clientFactory() throws Exception {
		return context().getSocketFactory();
	}

	/** What the scripted server does with one connection, after reading the request head. */
	@FunctionalInterface
	public interface Script {

		void respond(String requestHead, OutputStream out) throws Exception;

	}

	/** A TLS server on 127.0.0.1 that answers every connection with the same script. */
	public static final class Server implements AutoCloseable {

		private final ServerSocket socket;

		private final List<String> requests = new CopyOnWriteArrayList<>();

		private final Thread thread;

		public Server(Script script) throws Exception {
			this(script, true);
		}

		public Server(Script script, boolean tls) throws Exception {
			this.socket = tls ? context().getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress())
					: new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
			if (this.socket instanceof SSLServerSocket s) {
				s.setNeedClientAuth(false);
			}
			this.thread = new Thread(() -> {
				while (!this.socket.isClosed()) {
					try {
						Socket client = this.socket.accept();
						Thread handler = new Thread(() -> handle(client, script, tls));
						handler.setDaemon(true);
						handler.start();
					}
					catch (IOException ex) {
						return;
					}
				}
			});
			this.thread.setDaemon(true);
			this.thread.start();
		}

		private void handle(Socket client, Script script, boolean tls) {
			try (client) {
				if (!tls) {
					// A plain socket that never speaks: used to simulate a stalled TLS handshake.
					script.respond("", client.getOutputStream());
					return;
				}
				InputStream in = client.getInputStream();
				StringBuilder head = new StringBuilder();
				int b;
				while ((b = in.read()) != -1) {
					head.append((char) b);
					if (head.toString().endsWith("\r\n\r\n")) {
						break;
					}
				}
				this.requests.add(head.toString());
				script.respond(head.toString(), client.getOutputStream());
			}
			catch (Exception ex) {
				// the fetcher closed the connection: expected in the negative tests
			}
		}

		public int port() {
			return this.socket.getLocalPort();
		}

		public List<String> requests() {
			return this.requests;
		}

		/** A connector that records the requested address and connects to this server instead. */
		public SocketConnector connector(List<InetAddress> recorded) {
			return (address, port, timeout) -> {
				recorded.add(address);
				Socket s = new Socket();
				s.connect(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), port()), timeout);
				return s;
			};
		}

		@Override
		public void close() throws IOException {
			this.socket.close();
		}

	}

}
