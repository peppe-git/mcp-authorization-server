// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipal;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.spi.ScopePolicy;

/** The SPI decides: a disabled user loses access on the next request, and scopes can be narrowed. */
@SpringBootTest(classes = { TestMcpApplication.class, InactiveSubjectTest.Policies.class })
@AutoConfigureMockMvc
class InactiveSubjectTest {

	static final Set<String> DISABLED = ConcurrentHashMap.newKeySet();

	@TestConfiguration
	static class Policies {

		@Bean
		McpPrincipalResolver principals() {
			return new McpPrincipalResolver() {
				@Override
				public Optional<McpPrincipal> resolve(Authentication authentication) {
					return Optional.of(new McpPrincipal("user:" + authentication.getName(), authentication.getName()));
				}

				@Override
				public boolean isActive(String subject) {
					return !DISABLED.contains(subject);
				}
			};
		}

		@Bean
		ScopePolicy scopes() {
			return new ScopePolicy() {
				@Override
				public Set<String> grantableScopes(McpPrincipal principal, String clientId, Set<String> requested) {
					// bob may only read
					return principal.subject().equals("user:bob") ? Set.of("tools.read") : requested;
				}
			};
		}

	}

	@Autowired
	MockMvc mvc;

	@Autowired
	TestMcpApplication.Events events;

	@Test
	void aDisabledUserLosesAccessAndTheGrantOnRefresh() throws Exception {
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		Map<String, Object> t = client.tokens("test-cli", "https://client.example/callback", "carol");
		client.callMcp((String) t.get("access_token")).andExpect(jsonPath("$.sub").value("user:carol"));
		DISABLED.add("user:carol");
		client.callMcp((String) t.get("access_token")).andExpect(status().isUnauthorized());
		client.refresh("test-cli", (String) t.get("refresh_token")).andExpect(jsonPath("$.error").value("invalid_grant"));
		DISABLED.remove("user:carol");
		// The grant was revoked by the refresh: re-enabling the user does not bring it back.
		client.refresh("test-cli", (String) t.get("refresh_token")).andExpect(jsonPath("$.error").value("invalid_grant"));
		assertThat(this.events.received).anySatisfy(e -> assertThat(e).isInstanceOfSatisfying(
				McpAuthorizationEvent.GrantRevoked.class,
				r -> assertThat(r.reason()).isEqualTo(McpAuthorizationEvent.RevocationReason.SUBJECT_INACTIVE)));
	}

	@Test
	void theScopePolicyNarrowsTheGrant() throws Exception {
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		var p = client.authorizeParams("test-cli", "https://client.example/callback");
		p.set("scope", "tools.read tools.write");
		String requestId = OAuthClientSimulator.requestId(client.authorize(p));
		String code = OAuthClientSimulator.query(client.decide(requestId, "bob", "approve").getHeader("Location"))
			.getFirst("code");
		client.exchange("test-cli", code, client.verifier, "https://client.example/callback")
			.andExpect(jsonPath("$.scope").value("tools.read"));
	}

}
