// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import static io.github.peppe_git.mcpauthserver.store.JdbcTimes.param;
import static io.github.peppe_git.mcpauthserver.store.JdbcTimes.read;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/**
 * {@link AuthorizationStateStore} on the {@code mcp_oauth_authorization_request} and
 * {@code mcp_oauth_authorization_code} tables. {@code take*} reads and deletes in one transaction; of two
 * concurrent takes only the one whose {@code DELETE} removes the row returns it.
 */
public final class JdbcAuthorizationStateStore implements AuthorizationStateStore {

	private static final String REQUEST_COLUMNS = "request_id, client_id, client_name, client_verification, "
			+ "verified_domain, redirect_uri, code_challenge, scopes, state, resource, expires_at";

	private static final String CODE_COLUMNS = "client_id, client_name, redirect_uri, code_challenge, scopes, "
			+ "resource, subject, expires_at";

	private static final RowMapper<PendingAuthorization> REQUEST = (rs, n) -> new PendingAuthorization(
			rs.getString("request_id"), rs.getString("client_id"), rs.getString("client_name"),
			ClientVerification.valueOf(rs.getString("client_verification")), rs.getString("verified_domain"),
			rs.getString("redirect_uri"), rs.getString("code_challenge"), scopes(rs.getString("scopes")),
			rs.getString("state"), rs.getString("resource"), read(rs, "expires_at"));

	private static final RowMapper<IssuedCode> CODE = (rs, n) -> new IssuedCode(rs.getString("client_id"),
			rs.getString("client_name"), rs.getString("redirect_uri"), rs.getString("code_challenge"),
			scopes(rs.getString("scopes")), rs.getString("resource"), rs.getString("subject"),
			read(rs, "expires_at"));

	private final JdbcTemplate jdbc;

	private final TransactionTemplate tx;

	public JdbcAuthorizationStateStore(JdbcTemplate jdbc, TransactionTemplate tx) {
		this.jdbc = jdbc;
		this.tx = tx;
	}

	@Override
	public void saveRequest(PendingAuthorization r) {
		this.jdbc.update("INSERT INTO mcp_oauth_authorization_request (" + REQUEST_COLUMNS
				+ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", r.requestId(), r.clientId(), r.clientName(),
				r.verification().name(), r.verifiedDomain(), r.redirectUri(), r.codeChallenge(),
				String.join(" ", r.scopes()), r.state(), r.resource(), param(r.expiresAt()));
	}

	@Override
	public Optional<PendingAuthorization> findRequest(String requestId, Instant now) {
		if (requestId == null) {
			return Optional.empty();
		}
		return this.jdbc
			.query("SELECT " + REQUEST_COLUMNS + " FROM mcp_oauth_authorization_request WHERE request_id = ? AND expires_at > ?",
					REQUEST, requestId, param(now))
			.stream()
			.findFirst();
	}

	@Override
	public Optional<PendingAuthorization> takeRequest(String requestId, Instant now) {
		if (requestId == null) {
			return Optional.empty();
		}
		return this.tx.execute(s -> {
			List<PendingAuthorization> rows = this.jdbc.query(
					"SELECT " + REQUEST_COLUMNS + " FROM mcp_oauth_authorization_request WHERE request_id = ?", REQUEST,
					requestId);
			int deleted = this.jdbc.update("DELETE FROM mcp_oauth_authorization_request WHERE request_id = ?", requestId);
			return rows.stream().filter(r -> deleted == 1 && r.expiresAt().isAfter(now)).findFirst();
		});
	}

	@Override
	public void saveCode(String codeHash, IssuedCode c) {
		this.jdbc.update("INSERT INTO mcp_oauth_authorization_code (code_hash, " + CODE_COLUMNS
				+ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", codeHash, c.clientId(), c.clientName(), c.redirectUri(),
				c.codeChallenge(), String.join(" ", c.scopes()), c.resource(), c.subject(), param(c.expiresAt()));
	}

	@Override
	public Optional<IssuedCode> takeCode(String codeHash, Instant now) {
		if (codeHash == null) {
			return Optional.empty();
		}
		return this.tx.execute(s -> {
			List<IssuedCode> rows = this.jdbc.query(
					"SELECT " + CODE_COLUMNS + " FROM mcp_oauth_authorization_code WHERE code_hash = ?", CODE, codeHash);
			int deleted = this.jdbc.update("DELETE FROM mcp_oauth_authorization_code WHERE code_hash = ?", codeHash);
			return rows.stream().filter(c -> deleted == 1 && c.expiresAt().isAfter(now)).findFirst();
		});
	}

	@Override
	public int purgeExpired(Instant now) {
		return this.jdbc.update("DELETE FROM mcp_oauth_authorization_request WHERE expires_at <= ?", param(now))
				+ this.jdbc.update("DELETE FROM mcp_oauth_authorization_code WHERE expires_at <= ?", param(now));
	}

	private static List<String> scopes(String column) {
		return (column == null || column.isBlank()) ? List.of() : Arrays.asList(column.split(" "));
	}

}
