// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;
import io.github.peppe_git.mcpauthserver.store.JdbcTimes;

/** {@link ClientStore} on the {@code mcp_oauth_client} table (see {@code schema-postgresql.sql}). */
public final class JdbcClientStore implements ClientStore {

	private final JdbcTemplate jdbc;

	private final Clock clock;

	public JdbcClientStore(JdbcTemplate jdbc, Clock clock) {
		this.jdbc = jdbc;
		this.clock = clock;
	}

	@Override
	public Optional<RegisteredClient> findByClientId(String clientId) {
		if (clientId == null) {
			return Optional.empty();
		}
		List<RegisteredClient> rows = this.jdbc.query(
				"SELECT client_id, client_name, redirect_uris FROM mcp_oauth_client WHERE client_id = ?",
				(rs, n) -> new RegisteredClient(rs.getString(1), rs.getString(2),
						Arrays.asList(rs.getString(3).split("\n")), ClientVerification.NONE, null),
				clientId);
		return rows.stream().findFirst();
	}

	@Override
	public void save(RegisteredClient client) {
		this.jdbc.update("INSERT INTO mcp_oauth_client (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)",
				client.clientId(), client.clientName(), String.join("\n", client.redirectUris()),
				JdbcTimes.param(Instant.now(this.clock)));
	}

}
