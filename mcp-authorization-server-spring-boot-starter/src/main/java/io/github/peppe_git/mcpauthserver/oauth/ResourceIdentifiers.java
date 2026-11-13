// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;

/**
 * Canonical form of a resource identifier (RFC 8707, RFC 9728): lower-case scheme and host, no default
 * port, no fragment, no trailing slash. Two identifiers name the same resource when their canonical
 * forms are equal.
 */
public final class ResourceIdentifiers {

	private ResourceIdentifiers() {
	}

	/** The canonical form, or empty if {@code value} is not an absolute http(s) URI without fragment. */
	public static Optional<String> canonical(String value) {
		if (value == null || value.isBlank() || value.length() > 2048) {
			return Optional.empty();
		}
		URI u;
		try {
			u = new URI(value.strip());
		}
		catch (URISyntaxException ex) {
			return Optional.empty();
		}
		if (!u.isAbsolute() || u.isOpaque() || u.getHost() == null || u.getRawFragment() != null
				|| u.getRawUserInfo() != null) {
			return Optional.empty();
		}
		String scheme = u.getScheme().toLowerCase(Locale.ROOT);
		if (!scheme.equals("https") && !scheme.equals("http")) {
			return Optional.empty();
		}
		int port = u.getPort();
		boolean defaultPort = port == -1 || (scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80);
		String path = u.getRawPath() == null ? "" : u.getRawPath();
		while (path.endsWith("/")) {
			path = path.substring(0, path.length() - 1);
		}
		StringBuilder sb = new StringBuilder(scheme).append("://").append(u.getHost().toLowerCase(Locale.ROOT));
		if (!defaultPort) {
			sb.append(':').append(port);
		}
		sb.append(path);
		if (u.getRawQuery() != null) {
			sb.append('?').append(u.getRawQuery());
		}
		return Optional.of(sb.toString());
	}

	/** True if both values are valid and name the same resource. */
	public static boolean same(String a, String b) {
		Optional<String> ca = canonical(a);
		return ca.isPresent() && ca.equals(canonical(b));
	}

}
