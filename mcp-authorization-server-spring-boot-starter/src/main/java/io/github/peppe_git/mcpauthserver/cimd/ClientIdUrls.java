// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

/**
 * Syntax rules for a client identifier that is a URL (CIMD draft -03 §3): {@code https}, a host, a path
 * other than {@code /}, no fragment, no user info, no {@code .} or {@code ..} segments.
 */
public final class ClientIdUrls {

	/** Upper bound on the length of a client identifier URL. */
	public static final int MAX_LENGTH = 2048;

	private ClientIdUrls() {
	}

	/** True if {@code clientId} has the shape of a metadata document URL and should be fetched. */
	public static boolean looksLikeUrl(String clientId) {
		return clientId != null && clientId.startsWith("https://");
	}

	/** Validates the URL and its port; returns the parsed URI. */
	public static URI validate(String clientId, Set<Integer> allowedPorts) throws ClientMetadataException {
		if (clientId == null || clientId.length() > MAX_LENGTH) {
			throw new ClientMetadataException("client_id is missing or too long");
		}
		URI uri;
		try {
			uri = new URI(clientId);
		}
		catch (URISyntaxException ex) {
			throw new ClientMetadataException("client_id is not a valid URL");
		}
		if (!"https".equals(uri.getScheme()) || uri.isOpaque() || uri.getHost() == null || uri.getHost().isEmpty()) {
			throw new ClientMetadataException("client_id must be an https URL with a host");
		}
		if (uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
			throw new ClientMetadataException("client_id must not contain a fragment or user info");
		}
		String path = uri.getRawPath();
		if (path == null || path.isEmpty() || path.equals("/")) {
			throw new ClientMetadataException("client_id must have a path other than /");
		}
		for (String segment : path.split("/", -1)) {
			String s = segment.toLowerCase(Locale.ROOT).replace("%2e", ".");
			if (s.equals(".") || s.equals("..")) {
				throw new ClientMetadataException("client_id must not contain dot segments");
			}
		}
		int port = (uri.getPort() == -1) ? 443 : uri.getPort();
		if (!allowedPorts.contains(port)) {
			throw new ClientMetadataException("client_id port " + port + " is not allowed");
		}
		return uri;
	}

}
