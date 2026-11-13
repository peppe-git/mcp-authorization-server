// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** {@link ClientStore} for tests and single-instance deployments. Registrations are lost on restart. */
public final class InMemoryClientStore implements ClientStore {

	private final Map<String, RegisteredClient> clients = new ConcurrentHashMap<>();

	@Override
	public Optional<RegisteredClient> findByClientId(String clientId) {
		return clientId == null ? Optional.empty() : Optional.ofNullable(this.clients.get(clientId));
	}

	@Override
	public void save(RegisteredClient client) {
		this.clients.put(client.clientId(), client);
	}

}
