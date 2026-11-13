// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.util.List;
import java.util.Objects;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/**
 * A public OAuth client known to the server.
 *
 * @param clientId the identifier the client presents
 * @param clientName a display name, already sanitized
 * @param redirectUris the registered redirect URIs
 * @param verification how the identity was established
 * @param verifiedDomain for metadata-document clients, the host of the client identifier
 */
public record RegisteredClient(String clientId, String clientName, List<String> redirectUris,
		ClientVerification verification, String verifiedDomain) {

	public RegisteredClient {
		Objects.requireNonNull(clientId, "clientId");
		Objects.requireNonNull(clientName, "clientName");
		Objects.requireNonNull(verification, "verification");
		redirectUris = List.copyOf(redirectUris);
	}

}
