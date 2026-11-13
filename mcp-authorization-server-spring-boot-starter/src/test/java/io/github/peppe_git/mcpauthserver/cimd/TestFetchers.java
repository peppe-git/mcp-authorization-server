// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.CopyOnWriteArrayList;

/** Builds fetchers that keep the real address policy but connect to a local test server. */
public final class TestFetchers {

	private TestFetchers() {
	}

	/** Every host resolves to one public address, and every connection goes to {@code server}. */
	public static MetadataDocumentFetcher toLocalServer(TestTls.Server server) throws Exception {
		InetAddress publicAddress = InetAddress.getByName("93.184.216.34");
		return new MetadataDocumentFetcher(host -> new InetAddress[] { publicAddress }, AddressPolicy::isAllowed,
				server.connector(new CopyOnWriteArrayList<>()), TestTls.clientFactory(), Duration.ofSeconds(3), 5120);
	}

}
