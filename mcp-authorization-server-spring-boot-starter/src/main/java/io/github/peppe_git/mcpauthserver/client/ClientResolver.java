// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.util.Map;
import java.util.Optional;

import io.github.peppe_git.mcpauthserver.cimd.ClientIdUrls;
import io.github.peppe_git.mcpauthserver.cimd.ClientMetadataResolver;

/**
 * Finds the client behind a {@code client_id}: a URL is a Client ID Metadata Document (fetched, when
 * enabled), anything else is a pre-registered client from configuration or a dynamically registered
 * one.
 */
public final class ClientResolver {

	private final Map<String, RegisteredClient> preRegistered;

	private final ClientStore store;

	private final ClientMetadataResolver metadataDocuments;

	/**
	 * @param metadataDocuments null when metadata-document clients are disabled
	 */
	public ClientResolver(Map<String, RegisteredClient> preRegistered, ClientStore store,
			ClientMetadataResolver metadataDocuments) {
		this.preRegistered = Map.copyOf(preRegistered);
		this.store = store;
		this.metadataDocuments = metadataDocuments;
	}

	/** The client, or empty if unknown or if its metadata document cannot be used. */
	public Optional<RegisteredClient> resolve(String clientId) {
		if (clientId == null || clientId.isBlank() || clientId.length() > ClientIdUrls.MAX_LENGTH) {
			return Optional.empty();
		}
		RegisteredClient configured = this.preRegistered.get(clientId);
		if (configured != null) {
			return Optional.of(configured);
		}
		if (ClientIdUrls.looksLikeUrl(clientId)) {
			return (this.metadataDocuments == null) ? Optional.empty() : this.metadataDocuments.resolve(clientId);
		}
		return this.store.findByClientId(clientId);
	}

}
