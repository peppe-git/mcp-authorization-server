// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The scopes this server knows, in a stable order.
 *
 * <p>{@code offline_access} is always accepted and advertised but never stored: refresh tokens are
 * issued with every grant, because without them an MCP client would have to ask for consent again every
 * hour.
 */
public final class ScopeRegistry {

	/** The scope MCP clients may add to ask for a refresh token. */
	public static final String OFFLINE_ACCESS = "offline_access";

	/** RFC 6749 §3.3 scope-token. */
	private static final Pattern SCOPE_TOKEN = Pattern.compile("^[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,128}$");

	/**
	 * A scope.
	 * @param name the scope token
	 * @param description shown on the consent page
	 * @param isDefault granted when the client asks for no scope
	 */
	public record ScopeDefinition(String name, String description, boolean isDefault) {
	}

	private final Map<String, ScopeDefinition> scopes = new LinkedHashMap<>();

	public ScopeRegistry(List<ScopeDefinition> definitions) {
		for (ScopeDefinition d : definitions) {
			if (d.name() == null || !SCOPE_TOKEN.matcher(d.name()).matches() || d.name().equals(OFFLINE_ACCESS)) {
				throw new IllegalArgumentException("Invalid scope name: " + d.name());
			}
			if (this.scopes.put(d.name(), d) != null) {
				throw new IllegalArgumentException("Duplicate scope: " + d.name());
			}
		}
	}

	/** Every advertised scope, {@code offline_access} last. */
	public List<String> supported() {
		List<String> all = new ArrayList<>(this.scopes.keySet());
		all.add(OFFLINE_ACCESS);
		return all;
	}

	/** Scopes granted when the request names none: the defaults, or all scopes if none is marked default. */
	public List<String> defaults() {
		List<String> d = this.scopes.values().stream().filter(ScopeDefinition::isDefault).map(ScopeDefinition::name).toList();
		return d.isEmpty() ? List.copyOf(this.scopes.keySet()) : d;
	}

	/**
	 * The scopes of a {@code scope} parameter, in registry order, without {@code offline_access}. Empty
	 * if any value is unknown: an unknown scope is refused, not dropped, so the client learns that it did
	 * not get it.
	 */
	public Optional<List<String>> parse(String raw) {
		if (raw == null || raw.isBlank()) {
			return Optional.of(defaults());
		}
		Set<String> requested = new LinkedHashSet<>();
		for (String part : raw.strip().split(" +")) {
			if (part.equals(OFFLINE_ACCESS)) {
				continue;
			}
			if (!this.scopes.containsKey(part)) {
				return Optional.empty();
			}
			requested.add(part);
		}
		if (requested.isEmpty()) {
			return Optional.of(defaults());
		}
		return Optional.of(this.scopes.keySet().stream().filter(requested::contains).toList());
	}

	/** Orders a set of known scopes as the registry does. */
	public List<String> ordered(Set<String> names) {
		return this.scopes.keySet().stream().filter(names::contains).toList();
	}

	public String description(String name) {
		ScopeDefinition d = this.scopes.get(name);
		return (d == null || d.description() == null || d.description().isBlank()) ? name : d.description();
	}

}
