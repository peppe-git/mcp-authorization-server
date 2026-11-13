// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import io.github.peppe_git.mcpauthserver.core.GrantManagement;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;

/**
 * The whole flow as an MCP client sees it: discovery from the 401, authorization with PKCE, consent,
 * code exchange, MCP call, rotation, reuse detection and revocation.
 */
@SpringBootTest(classes = TestMcpApplication.class)
@AutoConfigureMockMvc
class AuthorizationServerFlowTest {

	static final String CLIENT = "test-cli";

	static final String LOOPBACK = "http://127.0.0.1:53682/callback";

	@Autowired
	MockMvc mvc;

	@Autowired
	TestMcpApplication.Events events;

	@Autowired
	TestMcpApplication.MutableClock clock;

	@Autowired
	GrantManagement grantManagement;

	OAuthClientSimulator client;

	@BeforeEach
	void setUp() {
		this.client = new OAuthClientSimulator(this.mvc);
		this.events.received.clear();
	}

	@Test
	void discoveryStartsFromThe401() throws Exception {
		this.mvc.perform(post("/mcp").contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string("WWW-Authenticate",
					"Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\", "
							+ "scope=\"tools.read\""));
		for (String path : new String[] { "/.well-known/oauth-protected-resource/mcp",
				"/.well-known/oauth-protected-resource" }) {
			this.mvc.perform(get(path))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.resource").value("http://localhost/mcp"))
				.andExpect(jsonPath("$.authorization_servers[0]").value("http://localhost"))
				.andExpect(jsonPath("$.scopes_supported").value(org.hamcrest.Matchers.contains("tools.read",
						"tools.write", "offline_access")))
				.andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"));
		}
		this.mvc.perform(get("/.well-known/oauth-protected-resource/other")).andExpect(status().isNotFound());
		this.mvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.issuer").value("http://localhost"))
			.andExpect(jsonPath("$.authorization_endpoint").value("http://localhost/oauth2/authorize"))
			.andExpect(jsonPath("$.token_endpoint").value("http://localhost/oauth2/token"))
			.andExpect(jsonPath("$.code_challenge_methods_supported.length()").value(1))
			.andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
			.andExpect(jsonPath("$.token_endpoint_auth_methods_supported").value(org.hamcrest.Matchers.contains("none")))
			.andExpect(jsonPath("$.authorization_response_iss_parameter_supported").value(true))
			.andExpect(jsonPath("$.client_id_metadata_document_supported").value(true))
			.andExpect(jsonPath("$.registration_endpoint").doesNotExist());
	}

	@Test
	void fullFlowRotationReuseDetectionAndEvents() throws Exception {
		MockHttpServletResponse authorize = this.client.authorize(this.client.authorizeParams(CLIENT, LOOPBACK));
		assertThat(authorize.getStatus()).isEqualTo(302);
		assertThat(authorize.getHeader("Location")).startsWith("/oauth2/consent?request_id=");
		String requestId = OAuthClientSimulator.requestId(authorize);

		// Not signed in yet: the consent page sends the browser to the application's login.
		MockHttpServletResponse anonymous = this.mvc
			.perform(get("/oauth2/consent").param("request_id", requestId).session(this.client.session))
			.andReturn()
			.getResponse();
		assertThat(anonymous.getStatus()).isEqualTo(302);
		assertThat(anonymous.getHeader("Location")).endsWith("/login");

		this.client.consentPage(requestId, "alice")
			.andExpect(status().isOk())
			.andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("frame-ancestors 'none'")))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("Test CLI")))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("registered by the operator")))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("this computer")))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("Read your test data")))
			.andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Change your test data"))));

		MockHttpServletResponse decided = this.client.decide(requestId, "alice", "approve");
		assertThat(decided.getStatus()).isEqualTo(303);
		var redirect = OAuthClientSimulator.query(decided.getHeader("Location"));
		assertThat(decided.getHeader("Location")).startsWith(LOOPBACK + "?code=");
		assertThat(redirect.getFirst("state")).isEqualTo("state-123");
		assertThat(redirect.getFirst("iss")).isEqualTo("http%3A%2F%2Flocalhost");
		String code = redirect.getFirst("code");

		Map<String, Object> t1 = OAuthClientSimulator.json(this.client.exchange(CLIENT, code, this.client.verifier, LOOPBACK)
			.andExpect(status().isOk())
			.andExpect(header().string("Cache-Control", "no-store"))
			.andExpect(jsonPath("$.token_type").value("Bearer"))
			.andExpect(jsonPath("$.expires_in").value(3600))
			.andExpect(jsonPath("$.scope").value("tools.read"))
			.andReturn()
			.getResponse()
			.getContentAsString());
		String access1 = (String) t1.get("access_token");
		String refresh1 = (String) t1.get("refresh_token");
		assertThat(access1).startsWith("mcp_at_");
		assertThat(refresh1).startsWith("mcp_rt_");

		this.client.callMcp(access1)
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.sub").value("alice"))
			// Spring Security 7 also adds its FACTOR_BEARER authority; the scopes are mapped by ScopePolicy.
			.andExpect(jsonPath("$.authorities").value(org.hamcrest.Matchers.hasItem("SCOPE_tools.read")))
			.andExpect(jsonPath("$.authorities").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem("SCOPE_tools.write"))));

		// Rotation: the old access token stops working, the new one works.
		Map<String, Object> t2 = OAuthClientSimulator.json(this.client.refresh(CLIENT, refresh1)
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString());
		String access2 = (String) t2.get("access_token");
		String refresh2 = (String) t2.get("refresh_token");
		assertThat(refresh2).isNotEqualTo(refresh1);
		this.client.callMcp(access1).andExpect(status().isUnauthorized())
			.andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.startsWith("Bearer error=\"invalid_token\"")));
		this.client.callMcp(access2).andExpect(status().isOk());

		// Replay of the rotated token after the grace window: the whole grant is revoked.
		this.clock.advance(Duration.ofMinutes(5));
		this.client.refresh(CLIENT, refresh1)
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"))
			.andExpect(jsonPath("$.error_description").value(org.hamcrest.Matchers.containsString("reuse")));
		this.client.callMcp(access2).andExpect(status().isUnauthorized());
		this.client.refresh(CLIENT, refresh2).andExpect(status().isBadRequest());

		assertThat(this.events.received).hasAtLeastOneElementOfType(McpAuthorizationEvent.GrantCreated.class)
			.hasAtLeastOneElementOfType(McpAuthorizationEvent.RefreshTokenReuseDetected.class)
			.anySatisfy(e -> assertThat(e).isInstanceOfSatisfying(McpAuthorizationEvent.GrantRevoked.class,
					r -> assertThat(r.reason()).isEqualTo(RevocationReason.REFRESH_TOKEN_REUSE)));
		// Events never carry a secret.
		for (McpAuthorizationEvent e : this.events.received) {
			assertThat(e.toString()).doesNotContain(access1, access2, refresh1, refresh2, code, this.client.verifier);
		}
	}

	@Test
	void concurrentRefreshWithinTheGraceKeepsTheGrant() throws Exception {
		Map<String, Object> t = this.client.tokens(CLIENT, LOOPBACK, "alice");
		String refresh = (String) t.get("refresh_token");
		Map<String, Object> a = OAuthClientSimulator.json(this.client.refresh(CLIENT, refresh)
			.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
		this.clock.advance(Duration.ofSeconds(5));
		Map<String, Object> b = OAuthClientSimulator.json(this.client.refresh(CLIENT, refresh)
			.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
		this.client.callMcp((String) a.get("access_token")).andExpect(status().isOk());
		this.client.callMcp((String) b.get("access_token")).andExpect(status().isOk());
	}

	@Test
	void theClientRevokesAndAccessEndsAtOnce() throws Exception {
		Map<String, Object> t = this.client.tokens(CLIENT, LOOPBACK, "alice");
		String access = (String) t.get("access_token");
		this.client.callMcp(access).andExpect(status().isOk());
		this.mvc.perform(post("/oauth2/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("token", (String) t.get("refresh_token"))
			.param("client_id", CLIENT)).andExpect(status().isOk());
		this.client.callMcp(access).andExpect(status().isUnauthorized());
		// Unknown tokens are also answered with 200, so the endpoint is not an oracle.
		this.mvc.perform(post("/oauth2/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("token", "mcp_rt_unknown")
			.param("client_id", CLIENT)).andExpect(status().isOk());
	}

	@Test
	void theUserDisconnectsAndAccountRecoveryRevokesEverything() throws Exception {
		Map<String, Object> first = this.client.tokens(CLIENT, LOOPBACK, "bob");
		this.clock.advance(Duration.ofSeconds(1));
		OAuthClientSimulator other = new OAuthClientSimulator(this.mvc);
		Map<String, Object> second = other.tokens(CLIENT, "https://client.example/callback", "bob");
		assertThat(this.grantManagement.activeGrants("bob")).hasSize(2);

		String grantId = this.grantManagement.activeGrants("bob").get(1).grantId();
		assertThat(this.grantManagement.revoke("alice", grantId)).isFalse();
		assertThat(this.grantManagement.revoke("bob", grantId)).isTrue();
		this.client.callMcp((String) first.get("access_token")).andExpect(status().isUnauthorized());
		other.callMcp((String) second.get("access_token")).andExpect(status().isOk());

		assertThat(this.grantManagement.revokeAll("bob")).isEqualTo(1);
		other.callMcp((String) second.get("access_token")).andExpect(status().isUnauthorized());
	}

	@Test
	void anAccessTokenOpensNothingButTheMcpEndpoint() throws Exception {
		String access = (String) this.client.tokens(CLIENT, LOOPBACK, "alice").get("access_token");
		int status = this.mvc.perform(get("/hello").header("Authorization", "Bearer " + access))
			.andReturn()
			.getResponse()
			.getStatus();
		assertThat(status).isIn(302, 401);
		this.mvc.perform(get("/hello").with(user("alice"))).andExpect(status().isOk());
	}

	@Test
	void theConsentPageEscapesTheClientName() throws Exception {
		String requestId = OAuthClientSimulator
			.requestId(this.client.authorize(this.client.authorizeParams("hostile-name", "https://client.example/callback")));
		String page = this.client.consentPage(requestId, "alice").andReturn().getResponse().getContentAsString();
		assertThat(page).doesNotContain("<img").doesNotContain("‮").contains("&lt;img src=x");
		assertThat(page).contains("client.example");
	}

	@Test
	void deniedConsentGoesBackToTheClient() throws Exception {
		String requestId = OAuthClientSimulator.requestId(this.client.authorize(this.client.authorizeParams(CLIENT, LOOPBACK)));
		MockHttpServletResponse denied = this.client.decide(requestId, "alice", "deny");
		assertThat(denied.getHeader("Location")).startsWith(LOOPBACK + "?error=access_denied")
			.contains("state=state-123")
			.contains("iss=");
		assertThat(this.events.received).hasAtLeastOneElementOfType(McpAuthorizationEvent.ConsentDenied.class);
		// The request was consumed.
		assertThat(this.client.decide(requestId, "alice", "approve").getStatus()).isEqualTo(400);
	}

	@Test
	void theDefaultSecurityChainStillProtectsTheRestOfTheApplication() throws Exception {
		int status = this.mvc.perform(get("/hello")).andReturn().getResponse().getStatus();
		assertThat(status).isIn(302, 401);
	}

}
