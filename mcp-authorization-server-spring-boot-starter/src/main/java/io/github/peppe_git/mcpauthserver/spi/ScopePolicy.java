// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Maps OAuth scopes to what a user may grant and to what an MCP request may do.
 *
 * <p>The default grants every requested scope and turns scope {@code x} into the authority
 * {@code SCOPE_x}, like Spring Security's resource server.
 */
public interface ScopePolicy {

	/**
	 * The scopes this principal may grant to this client. {@code requested} contains only supported
	 * scopes. Returning a subset narrows the grant; returning an empty set refuses the request with
	 * {@code access_denied}.
	 */
	default Set<String> grantableScopes(McpPrincipal principal, String clientId, Set<String> requested) {
		return requested;
	}

	/** The authorities of an MCP request authenticated with a token that carries {@code scopes}. */
	default Collection<GrantedAuthority> authorities(Set<String> scopes) {
		return scopes.stream().<GrantedAuthority>map(s -> new SimpleGrantedAuthority("SCOPE_" + s)).toList();
	}

	/** A policy with the default behaviour. */
	static ScopePolicy defaults() {
		return new ScopePolicy() {
		};
	}

}
