// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.peppe_git.mcpauthserver.client.RegisteredClient;
import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

class ClientMetadataDocumentTest {

	private static final String ID = "https://client.example/oauth/client.json";

	@Test
	void validDocument() throws Exception {
		RegisteredClient c = parse("{\"client_id\":\"" + ID + "\",\"client_name\":\"Example‮ tnemyap\","
				+ "\"redirect_uris\":[\"https://client.example/cb\",\"http://localhost/cb\"],"
				+ "\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],"
				+ "\"token_endpoint_auth_method\":\"none\"}");
		assertThat(c.clientId()).isEqualTo(ID);
		assertThat(c.clientName()).isEqualTo("Example tnemyap"); // bidi override removed
		assertThat(c.redirectUris()).containsExactly("https://client.example/cb", "http://localhost/cb");
		assertThat(c.verification()).isEqualTo(ClientVerification.DOMAIN);
		assertThat(c.verifiedDomain()).isEqualTo("client.example");
	}

	@Test
	void nameFallsBackToTheHost() throws Exception {
		assertThat(parse("{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://client.example/cb\"]}").clientName())
			.isEqualTo("client.example");
	}

	@Test
	void aDocumentCannotImpersonateAnotherClient() {
		assertThatThrownBy(() -> parse("{\"client_id\":\"https://other.example/client.json\","
				+ "\"redirect_uris\":[\"https://client.example/cb\"]}"))
			.isInstanceOf(ClientMetadataException.class)
			.hasMessageContaining("differs");
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://c.example/cb\"],\"client_secret\":\"s\"}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://c.example/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://c.example/cb\"],\"grant_types\":[\"client_credentials\"]}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://c.example/cb\"],\"response_types\":[\"token\"]}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[]}",
			"{\"client_id\":\"" + ID + "\"}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"http://client.example/cb\"]}",
			"{\"client_id\":\"" + ID + "\",\"redirect_uris\":[\"https://c.example/cb\", 42]}",
			"[1,2,3]", "not json", "" })
	void rejected(String json) {
		assertThatThrownBy(() -> parse(json)).isInstanceOf(ClientMetadataException.class);
	}

	@Test
	void malformedUtf8IsRejected() {
		byte[] body = { '{', '"', (byte) 0xC3, (byte) 0x28, '"', '}' };
		assertThatThrownBy(() -> ClientMetadataDocument.parse(ID, body)).isInstanceOf(ClientMetadataException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://client.example/c.json", "https://client.example", "https://client.example/",
			"https://client.example/a/../c.json", "https://client.example/./c.json", "https://client.example/%2e%2E/c.json",
			"https://client.example/c.json#f", "https://u:p@client.example/c.json", "https://client.example:8443/c.json",
			"https:///c.json", "https://client.example/ c.json" })
	void clientIdUrlRules(String url) {
		assertThatThrownBy(() -> ClientIdUrls.validate(url, Set.of(443))).isInstanceOf(ClientMetadataException.class);
	}

	@Test
	void clientIdUrlAccepted() throws Exception {
		assertThat(ClientIdUrls.validate(ID, Set.of(443)).getHost()).isEqualTo("client.example");
		assertThat(ClientIdUrls.validate("https://client.example:443/c.json?v=1", Set.of(443))).isNotNull();
		assertThat(ClientIdUrls.validate("https://client.example:8443/c.json", Set.of(443, 8443))).isNotNull();
	}

	private static RegisteredClient parse(String json) throws ClientMetadataException {
		return ClientMetadataDocument.parse(ID, json.getBytes(StandardCharsets.UTF_8));
	}

}
