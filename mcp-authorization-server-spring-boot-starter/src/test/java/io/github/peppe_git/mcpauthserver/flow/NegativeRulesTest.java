// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;

import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;

/** One negative test per rule of the authorization and token endpoints. */
@SpringBootTest(classes = TestMcpApplication.class)
@AutoConfigureMockMvc
class NegativeRulesTest {

	static final String CLIENT = "test-cli";

	static final String REDIRECT = "https://client.example/callback";

	@Autowired
	MockMvc mvc;

	OAuthClientSimulator client;

	@BeforeEach
	void setUp() {
		this.client = new OAuthClientSimulator(this.mvc);
	}

	// ── PKCE ────────────────────────────────────────────────────────────────────────────────────

	@Test
	void missingPkceIsRefused() throws Exception {
		MultiValueMap<String, String> p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.remove("code_challenge");
		p.remove("code_challenge_method");
		assertBackToClient(this.client.authorize(p), "invalid_request");
	}

	@Test
	void plainPkceIsRefused() throws Exception {
		MultiValueMap<String, String> p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("code_challenge_method", "plain");
		p.set("code_challenge", this.client.verifier.substring(0, 43));
		assertBackToClient(this.client.authorize(p), "invalid_request");
		p.remove("code_challenge_method");
		assertBackToClient(this.client.authorize(p), "invalid_request");
	}

	@Test
	void aMalformedChallengeIsRefused() throws Exception {
		MultiValueMap<String, String> p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("code_challenge", "too-short");
		assertBackToClient(this.client.authorize(p), "invalid_request");
	}

	@Test
	void aWrongVerifierBurnsTheCode() throws Exception {
		String code = this.client.code(CLIENT, REDIRECT, "alice");
		this.client.exchange(CLIENT, code, OpaqueTokens.random() + "-x", REDIRECT)
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
		this.client.exchange(CLIENT, code, this.client.verifier, REDIRECT)
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
	}

	@Test
	void aCodeIsExchangedOnlyOnce() throws Exception {
		String code = this.client.code(CLIENT, REDIRECT, "alice");
		this.client.exchange(CLIENT, code, this.client.verifier, REDIRECT).andExpect(status().isOk());
		this.client.exchange(CLIENT, code, this.client.verifier, REDIRECT)
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
	}

	@Test
	void theCodeIsBoundToClientRedirectAndResource() throws Exception {
		String code = this.client.code(CLIENT, REDIRECT, "alice");
		this.client.exchange("hostile-name", code, this.client.verifier, REDIRECT)
			.andExpect(jsonPath("$.error").value("invalid_grant"));
		code = this.client.code(CLIENT, REDIRECT, "alice");
		this.client.exchange(CLIENT, code, this.client.verifier, "http://127.0.0.1:9/callback")
			.andExpect(jsonPath("$.error").value("invalid_grant"));
		code = this.client.code(CLIENT, REDIRECT, "alice");
		this.client
			.token(Map.of("grant_type", "authorization_code", "client_id", CLIENT, "code", code, "code_verifier",
					this.client.verifier, "redirect_uri", REDIRECT, "resource", "https://other.example/mcp"))
			.andExpect(jsonPath("$.error").value("invalid_target"));
	}

	// ── client and redirect: never redirect to an unverified address ────────────────────────────

	@Test
	void anUnregisteredRedirectIsNeverFollowed() throws Exception {
		for (String redirect : new String[] { "https://evil.example/callback", "https://client.example/callback/x",
				"https://client.example/callback?x=1", "http://localhost:8080/callback", "http://127.0.0.1:1/other" }) {
			MockHttpServletResponse r = this.client.authorize(this.client.authorizeParams(CLIENT, redirect));
			assertThat(r.getStatus()).as(redirect).isEqualTo(400);
			assertThat(r.getHeader("Location")).as(redirect).isNull();
		}
	}

	@Test
	void anUnknownClientIsAnErrorPage() throws Exception {
		MockHttpServletResponse r = this.client.authorize(this.client.authorizeParams("nobody", REDIRECT));
		assertThat(r.getStatus()).isEqualTo(400);
		assertThat(r.getHeader("Location")).isNull();
		assertThat(r.getContentAsString()).contains("invalid_client");
	}

	@ParameterizedTest
	@ValueSource(strings = { "https://127.0.0.1/client.json", "https://10.0.0.1/client.json",
			"https://169.254.169.254/latest/meta-data", "https://localhost/client.json",
			"https://[::ffff:127.0.0.1]/client.json", "https://[64:ff9b::a9fe:a9fe]/client.json",
			"https://[fd00::1]/client.json", "https://client.example/a/../client.json", "https://client.example:8443/c.json",
			"https://client.example/" })
	void aMetadataDocumentClientOnAnInternalOrMalformedUrlIsRefused(String clientId) throws Exception {
		MockHttpServletResponse r = this.client.authorize(this.client.authorizeParams(clientId, REDIRECT));
		assertThat(r.getStatus()).isEqualTo(400);
		assertThat(r.getHeader("Location")).isNull();
	}

	// ── other authorization request rules ──────────────────────────────────────────────────────

	@Test
	void repeatedParametersAreRefused() throws Exception {
		MultiValueMap<String, String> p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.add("client_id", "hostile-name");
		assertThat(this.client.authorize(p).getStatus()).isEqualTo(400);
		p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.add("scope", "tools.write");
		assertBackToClient(this.client.authorize(p), "invalid_request");
	}

	@Test
	void unsupportedResponseTypeScopeAndResource() throws Exception {
		MultiValueMap<String, String> p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("response_type", "token");
		assertBackToClient(this.client.authorize(p), "unsupported_response_type");
		p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("scope", "tools.read admin");
		assertBackToClient(this.client.authorize(p), "invalid_scope");
		p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("resource", "https://other.example/mcp");
		assertBackToClient(this.client.authorize(p), "invalid_target");
		p = this.client.authorizeParams(CLIENT, REDIRECT);
		p.set("request_uri", "urn:example:x");
		assertBackToClient(this.client.authorize(p), "request_not_supported");
	}

	@Test
	void theConsentBelongsToTheBrowserSessionThatStartedIt() throws Exception {
		String requestId = OAuthClientSimulator.requestId(this.client.authorize(this.client.authorizeParams(CLIENT, REDIRECT)));
		OAuthClientSimulator victim = new OAuthClientSimulator(this.mvc);
		victim.consentPage(requestId, "bob").andExpect(status().isBadRequest());
		assertThat(victim.decide(requestId, "bob", "approve").getStatus()).isEqualTo(400);
		// The request is still usable by the browser that opened it.
		this.client.consentPage(requestId, "alice").andExpect(status().isOk());
	}

	@Test
	void theConsentFormNeedsCsrf() throws Exception {
		String requestId = OAuthClientSimulator.requestId(this.client.authorize(this.client.authorizeParams(CLIENT, REDIRECT)));
		this.mvc.perform(post("/oauth2/consent").param("request_id", requestId).param("decision", "approve")
			.session(this.client.session)
			.with(user("alice"))).andExpect(status().isForbidden());
	}

	// ── token endpoint ─────────────────────────────────────────────────────────────────────────

	@Test
	void confidentialClientAuthenticationIsRefused() throws Exception {
		String code = this.client.code(CLIENT, REDIRECT, "alice");
		Map<String, String> form = new HashMap<>(Map.of("grant_type", "authorization_code", "client_id", CLIENT, "code",
				code, "code_verifier", this.client.verifier, "redirect_uri", REDIRECT));
		form.put("client_secret", "s3cret");
		this.client.token(form).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
		this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.header("Authorization", "Basic dGVzdDp0ZXN0")
			.param("grant_type", "refresh_token")
			.param("refresh_token", "mcp_rt_x")
			.param("client_id", CLIENT)).andExpect(status().isUnauthorized());
	}

	@Test
	void malformedTokenRequests() throws Exception {
		this.client.token(Map.of("grant_type", "password", "client_id", CLIENT))
			.andExpect(jsonPath("$.error").value("unsupported_grant_type"));
		this.client.token(Map.of("grant_type", "authorization_code", "client_id", CLIENT))
			.andExpect(jsonPath("$.error").value("invalid_request"));
		this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("grant_type", "refresh_token")
			.param("grant_type", "refresh_token")
			.param("client_id", CLIENT)
			.param("refresh_token", "mcp_rt_x")).andExpect(jsonPath("$.error").value("invalid_request"));
		this.mvc.perform(post("/oauth2/token?refresh_token=mcp_rt_x").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("grant_type", "refresh_token")
			.param("client_id", CLIENT)).andExpect(jsonPath("$.error").value("invalid_request"));
	}

	@Test
	void refreshIsBoundToTheClientAndTheGrantScope() throws Exception {
		Map<String, Object> t = this.client.tokens(CLIENT, REDIRECT, "alice");
		String refresh = (String) t.get("refresh_token");
		this.client.refresh("hostile-name", refresh).andExpect(jsonPath("$.error").value("invalid_grant"));
		this.client.token(Map.of("grant_type", "refresh_token", "client_id", CLIENT, "refresh_token", refresh, "scope",
				"tools.read tools.write")).andExpect(jsonPath("$.error").value("invalid_scope"));
		this.client.token(Map.of("grant_type", "refresh_token", "client_id", CLIENT, "refresh_token", refresh,
				"resource", "https://other.example/mcp")).andExpect(jsonPath("$.error").value("invalid_target"));
		// None of the refusals consumed the token or harmed the grant.
		this.client.refresh(CLIENT, refresh).andExpect(status().isOk());
	}

	@Test
	void dynamicRegistrationIsOffByDefault() throws Exception {
		this.mvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON)
			.content("{\"redirect_uris\":[\"https://client.example/callback\"]}")).andExpect(status().isNotFound());
	}

	@Test
	void anInvalidBearerOnTheMcpEndpointSaysInvalidToken() throws Exception {
		this.mvc.perform(post("/mcp").header("Authorization", "Bearer mcp_at_forged").content("{}"))
			.andExpect(status().isUnauthorized())
			.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
				.string("WWW-Authenticate", org.hamcrest.Matchers.startsWith("Bearer error=\"invalid_token\"")));
		this.mvc.perform(get("/mcp").header("Authorization", "Bearer " + "x".repeat(20)))
			.andExpect(status().isUnauthorized());
	}

	@Autowired
	io.github.peppe_git.mcpauthserver.store.GrantStore grantStore;

	@Autowired
	TestMcpApplication.MutableClock clock;

	@Test
	void aTokenIssuedForAnotherResourceIsRefused() throws Exception {
		String access = OpaqueTokens.newAccessToken();
		java.time.Instant now = this.clock.instant();
		this.grantStore.createGrant("alice", CLIENT, "Test CLI", java.util.List.of("tools.read"),
				"https://other.example/mcp", new io.github.peppe_git.mcpauthserver.store.TokenHashes(
						OpaqueTokens.hash(access), OpaqueTokens.hash(OpaqueTokens.newRefreshToken()), now,
						now.plusSeconds(3600), now.plusSeconds(86400)));
		this.client.callMcp(access).andExpect(status().isUnauthorized());
	}

	private static void assertBackToClient(MockHttpServletResponse r, String error) {
		assertThat(r.getStatus()).isEqualTo(302);
		assertThat(r.getHeader("Location")).startsWith(REDIRECT + "?error=" + error).contains("iss=");
	}

}
