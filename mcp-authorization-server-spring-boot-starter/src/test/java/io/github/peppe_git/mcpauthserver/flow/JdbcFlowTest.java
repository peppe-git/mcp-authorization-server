// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import io.github.peppe_git.mcpauthserver.store.GrantStore;
import io.github.peppe_git.mcpauthserver.store.JdbcGrantStore;

/** The same flow with {@code store: jdbc} on PostgreSQL, wired by auto-configuration. */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = TestMcpApplication.class,
		properties = { "spring.autoconfigure.exclude=", "mcp.authorization-server.store=jdbc", "spring.sql.init.mode=always",
				"spring.sql.init.schema-locations=classpath:io/github/peppe_git/mcpauthserver/store/schema-postgresql.sql" })
@AutoConfigureMockMvc
class JdbcFlowTest {

	@Container
	@ServiceConnection
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine");

	@Autowired
	MockMvc mvc;

	@Autowired
	GrantStore grantStore;

	@Autowired
	JdbcTemplate jdbc;

	@Autowired
	TestMcpApplication.MutableClock clock;

	@Test
	void fullFlowOnPostgres() throws Exception {
		assertThat(this.grantStore).isInstanceOf(JdbcGrantStore.class);
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		Map<String, Object> t = client.tokens("test-cli", "https://client.example/callback", "alice");
		String refresh = (String) t.get("refresh_token");
		client.callMcp((String) t.get("access_token")).andExpect(status().isOk());
		Map<String, Object> t2 = OAuthClientSimulator.json(
				client.refresh("test-cli", refresh).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
		client.callMcp((String) t2.get("access_token")).andExpect(status().isOk());
		this.clock.advance(Duration.ofMinutes(5));
		client.refresh("test-cli", refresh).andExpect(status().isBadRequest());
		client.callMcp((String) t2.get("access_token")).andExpect(status().isUnauthorized());

		// Nothing secret is stored in clear.
		String everything = this.jdbc.queryForList("SELECT CONCAT(access_hash, refresh_hash) FROM mcp_oauth_token",
				String.class).toString();
		assertThat(everything).doesNotContain(refresh).doesNotContain((String) t.get("access_token"));
		assertThat(this.jdbc.queryForObject("SELECT revoked_reason FROM mcp_oauth_grant", String.class))
			.isEqualTo("REFRESH_TOKEN_REUSE");
	}

}
