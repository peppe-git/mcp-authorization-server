// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.util.Optional;

/**
 * Storage of dynamically registered clients (RFC 7591). Pre-registered clients come from configuration
 * and metadata-document clients are fetched, so neither is stored here.
 */
public interface ClientStore {

	Optional<RegisteredClient> findByClientId(String clientId);

	void save(RegisteredClient client);

}
