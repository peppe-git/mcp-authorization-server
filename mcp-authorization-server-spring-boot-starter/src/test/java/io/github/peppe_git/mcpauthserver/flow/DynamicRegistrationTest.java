// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** RFC 7591 registration when an operator turns it on: public clients only, sane redirects. */
@SpringBootTest(classes = TestMcpApplication.class, properties = "mcp.authorization-server.dcr.enabled=true")
@AutoConfigureMockMvc
class DynamicRegistrationTest {

	@Autowired
	MockMvc mvc;

	@Test
	void aPublicClientRegistersAndIsShownAsUnverified() throws Exception {
		this.mvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(jsonPath("$.registration_endpoint").value("http://localhost/oauth2/register"));
		String body = this.mvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON)
			.content("{\"client_name\":\"Self Registered\",\"redirect_uris\":[\"http://localhost/callback\"],"
					+ "\"token_endpoint_auth_method\":\"none\",\"grant_types\":[\"authorization_code\",\"refresh_token\"]}"))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").value(Matchers.startsWith("mcp_client_")))
			.andExpect(jsonPath("$.token_endpoint_auth_method").value("none"))
			.andReturn()
			.getResponse()
			.getContentAsString();
		String clientId = (String) OAuthClientSimulator.json(body).get("client_id");

		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		String requestId = OAuthClientSimulator
			.requestId(client.authorize(client.authorizeParams(clientId, "http://localhost:31337/callback")));
		client.consentPage(requestId, "alice")
			.andExpect(content().string(Matchers.containsString("not verified")))
			.andExpect(content().string(Matchers.containsString("Self Registered")));
		String code = OAuthClientSimulator.query(client.decide(requestId, "alice", "approve").getHeader("Location"))
			.getFirst("code");
		client.exchange(clientId, code, client.verifier, "http://localhost:31337/callback").andExpect(status().isOk());
	}

	@ParameterizedTest
	@ValueSource(strings = { "{\"redirect_uris\":[\"https://c.example/cb\"],\"token_endpoint_auth_method\":\"client_secret_basic\"}",
			"{\"redirect_uris\":[\"https://c.example/cb\"],\"grant_types\":[\"client_credentials\"]}",
			"{\"redirect_uris\":[\"https://c.example/cb\"],\"response_types\":[\"token\"]}",
			"{\"client_name\":42,\"redirect_uris\":[\"https://c.example/cb\"]}", "[1]", "not json" })
	void confidentialOrMalformedMetadataIsRefused(String json) throws Exception {
		this.mvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(json))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_client_metadata"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "{\"redirect_uris\":[]}", "{\"redirect_uris\":[\"http://c.example/cb\"]}",
			"{\"redirect_uris\":[\"https://c.example/cb#x\"]}", "{\"redirect_uris\":[\"javascript:alert(1)\"]}",
			"{}" })
	void badRedirectUrisAreRefused(String json) throws Exception {
		this.mvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(json))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
	}

	@Test
	void registrationNeedsNoCsrfButOnlyJson() throws Exception {
		int status = this.mvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("redirect_uris", "https://c.example/cb")).andReturn().getResponse().getStatus();
		assertThat(status).isEqualTo(415);
	}

}
