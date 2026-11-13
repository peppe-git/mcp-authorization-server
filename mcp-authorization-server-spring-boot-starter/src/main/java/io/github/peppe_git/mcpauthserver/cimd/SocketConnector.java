// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/** Opens a TCP connection to an already validated address. */
@FunctionalInterface
public interface SocketConnector {

	Socket connect(InetAddress address, int port, int timeoutMillis) throws IOException;

	/** A direct connection, without any proxy and without resolving names again. */
	static SocketConnector direct() {
		return (address, port, timeoutMillis) -> {
			Socket socket = new Socket(java.net.Proxy.NO_PROXY);
			try {
				socket.connect(new InetSocketAddress(address, port), Math.max(1, timeoutMillis));
				return socket;
			}
			catch (IOException ex) {
				socket.close();
				throw ex;
			}
		};
	}

}
