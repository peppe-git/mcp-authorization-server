// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Resolves a host name. The fetcher calls it exactly once per fetch and connects to what it returned. */
@FunctionalInterface
public interface HostResolver {

	InetAddress[] resolve(String host) throws UnknownHostException;

	/** The JVM resolver. */
	static HostResolver system() {
		return InetAddress::getAllByName;
	}

}
