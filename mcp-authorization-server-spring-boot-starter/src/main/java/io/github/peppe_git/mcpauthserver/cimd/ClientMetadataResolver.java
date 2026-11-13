// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import io.github.peppe_git.mcpauthserver.client.RegisteredClient;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;

/**
 * Turns a client identifier URL into a {@link RegisteredClient}: syntax and port checks, optional host
 * allow list, cache, fetch budget, then {@link MetadataDocumentFetcher} and
 * {@link ClientMetadataDocument}.
 *
 * <p>The authorization endpoint is public, so every check here is also about not letting it be used to
 * make the server knock on a host repeatedly: a global limit on concurrent fetches and a per-host budget
 * per minute. Errors are never cached (CIMD draft -03 §6.2); successful documents are cached for the
 * {@code Cache-Control: max-age} of the response, clamped to {@code [cacheMin, cacheMax]}.
 */
public final class ClientMetadataResolver {

	private static final Log logger = LogFactory.getLog(ClientMetadataResolver.class);

	/** Tuning of the resolver. */
	public record Settings(Set<Integer> allowedPorts, Set<String> allowedHosts, Duration cacheMin, Duration cacheMax,
			Duration cacheDefault, int maxCacheEntries, int maxConcurrentFetches, int maxFetchesPerHostPerMinute) {

		public Settings {
			allowedPorts = Set.copyOf(allowedPorts);
			allowedHosts = allowedHosts.stream().map(h -> h.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
		}

	}

	private record Cached(RegisteredClient client, Instant expiresAt) {
	}

	private record Window(long minute, int count) {
	}

	private final MetadataDocumentFetcher fetcher;

	private final Settings settings;

	private final Clock clock;

	private final Consumer<McpAuthorizationEvent> events;

	private final Semaphore concurrent;

	private final Map<String, Cached> cache;

	private final Map<String, Window> perHost = new ConcurrentHashMap<>();

	public ClientMetadataResolver(MetadataDocumentFetcher fetcher, Settings settings, Clock clock,
			Consumer<McpAuthorizationEvent> events) {
		this.fetcher = fetcher;
		this.settings = settings;
		this.clock = clock;
		this.events = events;
		this.concurrent = new Semaphore(Math.max(1, settings.maxConcurrentFetches()));
		int max = Math.max(1, settings.maxCacheEntries());
		this.cache = new LinkedHashMap<>(16, 0.75f, true) {
			@Override
			protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
				return size() > max;
			}
		};
	}

	/** The client described by the document at {@code clientId}, or empty if it cannot be used. */
	public Optional<RegisteredClient> resolve(String clientId) {
		try {
			return Optional.of(resolveOrThrow(clientId));
		}
		catch (ClientMetadataException ex) {
			logger.info("Client ID Metadata Document rejected (" + clientId + "): " + ex.getMessage());
			this.events.accept(new McpAuthorizationEvent.ClientMetadataRejected(Instant.now(this.clock), clientId,
					ex.getMessage()));
			return Optional.empty();
		}
	}

	RegisteredClient resolveOrThrow(String clientId) throws ClientMetadataException {
		URI uri = ClientIdUrls.validate(clientId, this.settings.allowedPorts());
		String host = uri.getHost().toLowerCase(Locale.ROOT);
		if (!this.settings.allowedHosts().isEmpty() && !this.settings.allowedHosts().contains(host)) {
			throw new ClientMetadataException("host " + host + " is not in the allowed hosts");
		}
		Instant now = Instant.now(this.clock);
		synchronized (this.cache) {
			Cached cached = this.cache.get(clientId);
			if (cached != null && cached.expiresAt().isAfter(now)) {
				return cached.client();
			}
		}
		chargeHostBudget(host, now);
		if (!this.concurrent.tryAcquire()) {
			throw new ClientMetadataException("too many metadata fetches in progress");
		}
		MetadataDocumentFetcher.Document doc;
		try {
			doc = this.fetcher.fetch(uri);
		}
		finally {
			this.concurrent.release();
		}
		RegisteredClient client = ClientMetadataDocument.parse(clientId, doc.body());
		Duration ttl = ttl(doc);
		synchronized (this.cache) {
			this.cache.put(clientId, new Cached(client, now.plus(ttl)));
		}
		return client;
	}

	private Duration ttl(MetadataDocumentFetcher.Document doc) {
		Duration ttl = doc.noStore() ? Duration.ZERO : (doc.maxAge() != null ? doc.maxAge() : this.settings.cacheDefault());
		if (ttl.compareTo(this.settings.cacheMin()) < 0) {
			ttl = this.settings.cacheMin();
		}
		if (ttl.compareTo(this.settings.cacheMax()) > 0) {
			ttl = this.settings.cacheMax();
		}
		return ttl;
	}

	private void chargeHostBudget(String host, Instant now) throws ClientMetadataException {
		long minute = now.getEpochSecond() / 60;
		if (this.perHost.size() > 10_000) {
			this.perHost.entrySet().removeIf(e -> e.getValue().minute() < minute);
		}
		Window w = this.perHost.compute(host,
				(h, old) -> (old == null || old.minute() != minute) ? new Window(minute, 1) : new Window(minute, old.count() + 1));
		if (w.count() > this.settings.maxFetchesPerHostPerMinute()) {
			throw new ClientMetadataException("fetch budget for host " + host + " exhausted");
		}
	}

}
