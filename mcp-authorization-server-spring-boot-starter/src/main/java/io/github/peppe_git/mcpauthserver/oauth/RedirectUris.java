// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Locale;
import java.util.Objects;

/**
 * Redirect URI rules.
 *
 * <ul>
 * <li>A redirect URI is absolute, has a host, no fragment and no user info, and is either {@code https}
 * or loopback {@code http} ({@code localhost}, {@code 127.0.0.1}, {@code [::1]}). The MCP specification
 * allows nothing else.</li>
 * <li>Matching is exact, character for character, except for loopback URIs: there the port is ignored,
 * because a native client listens on a port chosen at run time (RFC 8252 §7.3). Scheme, host, path and
 * query must still be identical: "any port" never becomes "any address".</li>
 * </ul>
 */
public final class RedirectUris {

	/** Upper bound on the length of a redirect URI. */
	public static final int MAX_LENGTH = 2048;

	private RedirectUris() {
	}

	/** True if {@code uri} has an acceptable form for a redirect URI. */
	public static boolean isWellFormed(String uri) {
		URI u = parse(uri);
		if (u == null || !u.isAbsolute() || u.getHost() == null || u.getRawFragment() != null
				|| u.getRawUserInfo() != null || u.isOpaque()) {
			return false;
		}
		return "https".equalsIgnoreCase(u.getScheme()) || isLoopback(u);
	}

	/** True if {@code candidate} matches at least one of the registered redirect URIs. */
	public static boolean matchesAny(String candidate, Collection<String> registered) {
		if (candidate == null || registered == null) {
			return false;
		}
		for (String r : registered) {
			if (matches(candidate, r)) {
				return true;
			}
		}
		return false;
	}

	/** Exact match, or loopback match with the port ignored. */
	public static boolean matches(String candidate, String registered) {
		if (candidate == null || registered == null || !isWellFormed(candidate)) {
			return false;
		}
		if (candidate.equals(registered)) {
			return true;
		}
		URI c = parse(candidate);
		URI r = parse(registered);
		if (c == null || r == null || !isLoopback(c) || !isLoopback(r)) {
			return false;
		}
		return c.getScheme().equalsIgnoreCase(r.getScheme()) && c.getHost().equalsIgnoreCase(r.getHost())
				&& Objects.equals(emptyToSlash(c.getRawPath()), emptyToSlash(r.getRawPath()))
				&& Objects.equals(c.getRawQuery(), r.getRawQuery());
	}

	/** True for a loopback {@code http} redirect URI, the only case where the port is free. */
	public static boolean isLoopback(String uri) {
		URI u = parse(uri);
		return u != null && isLoopback(u);
	}

	/** The host to show on the consent page: the user must recognise it. */
	public static String host(String uri) {
		URI u = parse(uri);
		return (u == null || u.getHost() == null) ? "" : u.getHost();
	}

	private static boolean isLoopback(URI u) {
		if (u.getScheme() == null || u.getHost() == null || !"http".equalsIgnoreCase(u.getScheme())) {
			return false;
		}
		String host = u.getHost().toLowerCase(Locale.ROOT);
		return host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
	}

	private static String emptyToSlash(String path) {
		return (path == null || path.isEmpty()) ? "/" : path;
	}

	private static URI parse(String value) {
		if (value == null || value.length() > MAX_LENGTH) {
			return null;
		}
		try {
			return new URI(value);
		}
		catch (URISyntaxException ex) {
			return null;
		}
	}

}
