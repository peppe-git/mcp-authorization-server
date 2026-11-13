// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.boot.json.JsonParserFactory;

import io.github.peppe_git.mcpauthserver.client.ClientNames;
import io.github.peppe_git.mcpauthserver.client.RegisteredClient;
import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/**
 * Validation of a Client ID Metadata Document (CIMD draft -03 §4) for a public client.
 *
 * <ul>
 * <li>The document must declare the <b>same</b> {@code client_id} as the URL it came from: otherwise a
 * document hosted anywhere could impersonate any client.</li>
 * <li>It must not carry a {@code client_secret}, and its {@code token_endpoint_auth_method} must be
 * absent or {@code none}: this server only serves public clients.</li>
 * <li>Every redirect URI must be HTTPS or loopback HTTP; one malformed entry rejects the document.</li>
 * <li>{@code grant_types} and {@code response_types}, when present, must allow the code flow.</li>
 * </ul>
 */
public final class ClientMetadataDocument {

	/** Upper bound on the number of redirect URIs in one document. */
	public static final int MAX_REDIRECT_URIS = 20;

	private ClientMetadataDocument() {
	}

	public static RegisteredClient parse(String clientId, byte[] body) throws ClientMetadataException {
		Map<String, Object> doc;
		try {
			String json = StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT)
				.decode(ByteBuffer.wrap(body))
				.toString();
			doc = JsonParserFactory.getJsonParser().parseMap(json);
		}
		catch (CharacterCodingException ex) {
			throw new ClientMetadataException("document is not UTF-8");
		}
		catch (IllegalArgumentException | ClassCastException ex) {
			throw new ClientMetadataException("document is not a JSON object");
		}
		if (doc == null) {
			throw new ClientMetadataException("document is not a JSON object");
		}
		if (!clientId.equals(doc.get("client_id"))) {
			throw new ClientMetadataException("client_id in the document differs from its URL");
		}
		if (doc.containsKey("client_secret") || doc.containsKey("client_secret_expires_at")) {
			throw new ClientMetadataException("document declares a client secret");
		}
		Object authMethod = doc.get("token_endpoint_auth_method");
		if (authMethod != null && !"none".equals(authMethod)) {
			throw new ClientMetadataException("token_endpoint_auth_method must be none for a public client");
		}
		requireIfPresent(doc, "grant_types", "authorization_code");
		requireIfPresent(doc, "response_types", "code");

		Object rawRedirects = doc.get("redirect_uris");
		if (!(rawRedirects instanceof List<?> list) || list.isEmpty() || list.size() > MAX_REDIRECT_URIS) {
			throw new ClientMetadataException("redirect_uris must list 1 to " + MAX_REDIRECT_URIS + " URIs");
		}
		List<String> redirects = new ArrayList<>();
		for (Object r : list) {
			if (!(r instanceof String s) || !RedirectUris.isWellFormed(s)) {
				throw new ClientMetadataException("redirect_uris contains a URI that is not https or loopback http");
			}
			redirects.add(s);
		}
		String host = URI.create(clientId).getHost();
		Object name = doc.get("client_name");
		String clientName = ClientNames.sanitize((name instanceof String s) ? s : null, host);
		return new RegisteredClient(clientId, clientName, redirects, ClientVerification.DOMAIN, host);
	}

	private static void requireIfPresent(Map<String, Object> doc, String field, String required)
			throws ClientMetadataException {
		Object value = doc.get(field);
		if (value == null) {
			return;
		}
		if (!(value instanceof List<?> list) || !list.contains(required)) {
			throw new ClientMetadataException(field + " must include " + required);
		}
	}

}
