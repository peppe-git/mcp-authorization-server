// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import static io.github.peppe_git.mcpauthserver.store.JdbcTimes.param;
import static io.github.peppe_git.mcpauthserver.store.JdbcTimes.read;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.store.RotationRules.Decision;
import io.github.peppe_git.mcpauthserver.store.RotationRules.Status;
import io.github.peppe_git.mcpauthserver.store.RotationRules.TokenState;

/**
 * {@link GrantStore} on the {@code mcp_oauth_grant} and {@code mcp_oauth_token} tables.
 *
 * <p>Every write that depends on the family runs in a transaction that first locks the grant row with
 * {@code SELECT … FOR UPDATE}: rotations of one family are serialised, so "is there still an active
 * sibling?" is decided without races. The family is re-read after the lock is taken.
 */
public final class JdbcGrantStore implements GrantStore {

	private static final Duration LAST_USED_RESOLUTION = Duration.ofMinutes(5);

	private static final String GRANT_COLUMNS = "g.grant_id, g.subject, g.client_id, g.client_name, g.scopes, "
			+ "g.resource, g.created_at, g.last_used_at, g.revoked_at, g.revoked_reason";

	private static final RowMapper<Grant> GRANT = (rs, n) -> new Grant(rs.getString("grant_id"),
			rs.getString("subject"), rs.getString("client_id"), rs.getString("client_name"),
			split(rs.getString("scopes")), rs.getString("resource"), read(rs, "created_at"),
			read(rs, "last_used_at"), read(rs, "revoked_at"),
			rs.getString("revoked_reason") == null ? null : RevocationReason.valueOf(rs.getString("revoked_reason")));

	private record TokenRow(TokenState state, String refreshHash) {
	}

	private static final RowMapper<TokenRow> TOKEN = (rs, n) -> new TokenRow(
			new TokenState(rs.getString("token_id"), read(rs, "created_at"), read(rs, "refresh_expires_at"),
					Status.valueOf(rs.getString("status")), read(rs, "ended_at"), read(rs, "first_used_at")),
			rs.getString("refresh_hash"));

	private final JdbcTemplate jdbc;

	private final TransactionTemplate tx;

	public JdbcGrantStore(JdbcTemplate jdbc, TransactionTemplate tx) {
		this.jdbc = jdbc;
		this.tx = tx;
	}

	@Override
	public Grant createGrant(String subject, String clientId, String clientName, List<String> scopes, String resource,
			TokenHashes firstPair) {
		Grant g = new Grant(OpaqueTokens.newId(), subject, clientId, clientName, scopes, resource, firstPair.issuedAt(),
				null, null, null);
		this.tx.executeWithoutResult(s -> {
			this.jdbc.update("INSERT INTO mcp_oauth_grant (grant_id, subject, client_id, client_name, scopes, resource, "
					+ "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", g.grantId(), subject, clientId, clientName,
					String.join(" ", scopes), resource, param(g.createdAt()));
			issue(g.grantId(), firstPair);
		});
		return g;
	}

	private void issue(String grantId, TokenHashes t) {
		this.jdbc.update("INSERT INTO mcp_oauth_token (token_id, grant_id, access_hash, refresh_hash, status, created_at, "
				+ "access_expires_at, refresh_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", OpaqueTokens.newId(), grantId,
				t.accessHash(), t.refreshHash(), Status.ACTIVE.name(), param(t.issuedAt()), param(t.accessExpiresAt()),
				param(t.refreshExpiresAt()));
	}

	@Override
	public Optional<AccessTokenInfo> findActiveAccessToken(String accessHash, Instant now) {
		return this.jdbc
			.query("SELECT " + GRANT_COLUMNS + ", t.token_id AS t_id, t.created_at AS t_created, "
					+ "t.access_expires_at AS t_expires FROM mcp_oauth_token t JOIN mcp_oauth_grant g ON g.grant_id = t.grant_id "
					+ "WHERE t.access_hash = ? AND t.status = 'ACTIVE' AND t.access_expires_at > ? AND g.revoked_at IS NULL",
					(rs, n) -> new AccessTokenInfo(GRANT.mapRow(rs, n), rs.getString("t_id"), read(rs, "t_created"),
							read(rs, "t_expires")),
					accessHash, param(now))
			.stream()
			.findFirst();
	}

	@Override
	public Rotation rotate(String refreshHash, String clientId, TokenHashes next, RefreshPolicy policy,
			Predicate<String> subjectActive, Function<Grant, String> refuse) {
		return this.tx.execute(s -> {
			Instant now = next.issuedAt();
			Optional<String> grantId = this.jdbc
				.queryForList("SELECT grant_id FROM mcp_oauth_token WHERE refresh_hash = ?", String.class, refreshHash)
				.stream()
				.findFirst();
			if (grantId.isEmpty()) {
				return Rotation.invalid("unknown");
			}
			Optional<Grant> locked = lockGrant(grantId.get());
			if (locked.isEmpty()) {
				return Rotation.invalid("unknown");
			}
			Grant g = locked.get();
			if (g.isRevoked()) {
				return Rotation.invalid("revoked", g, false);
			}
			if (!g.clientId().equals(clientId)) {
				return Rotation.invalid("wrong_client", g, false);
			}
			String refused = refuse.apply(g);
			if (refused != null) {
				return Rotation.invalid(refused, g, false);
			}
			List<TokenRow> family = this.jdbc.query("SELECT * FROM mcp_oauth_token WHERE grant_id = ? "
					+ "ORDER BY created_at, token_id", TOKEN, g.grantId());
			Optional<TokenRow> presented = family.stream().filter(t -> t.refreshHash().equals(refreshHash)).findFirst();
			if (presented.isEmpty()) {
				return Rotation.invalid("unknown");
			}
			TokenState p = presented.get().state();
			if (!p.refreshExpiresAt().isAfter(now)) {
				return Rotation.invalid("expired", g, false);
			}
			if (!subjectActive.test(g.subject())) {
				return Rotation.invalid("subject_inactive", revoke(g, RevocationReason.SUBJECT_INACTIVE, now), true);
			}
			Decision d = RotationRules.decide(p, family.stream().map(TokenRow::state).toList(), now, policy);
			switch (d.action()) {
				case ROTATE -> {
					this.jdbc.update("UPDATE mcp_oauth_token SET status = 'ROTATED', ended_at = ?, "
							+ "first_used_at = COALESCE(first_used_at, ?) WHERE token_id = ?", param(now), param(now),
							p.tokenId());
					issue(g.grantId(), next);
					return Rotation.rotated(g);
				}
				case SIBLING -> {
					issue(g.grantId(), next);
					return Rotation.rotated(g);
				}
				case RECOVER -> {
					for (String id : d.supersede()) {
						this.jdbc.update("UPDATE mcp_oauth_token SET status = 'SUPERSEDED', ended_at = ? WHERE token_id = ?",
								param(now), id);
					}
					issue(g.grantId(), next);
					return Rotation.rotated(g);
				}
				case EXPIRED -> {
					return Rotation.invalid("expired", g, false);
				}
				default -> {
					return Rotation.reuse(revoke(g, RevocationReason.REFRESH_TOKEN_REUSE, now));
				}
			}
		});
	}

	@Override
	public Optional<Grant> revokeByToken(String tokenHash, String clientId, Instant now) {
		return this.tx.execute(s -> {
			Optional<String> grantId = this.jdbc
				.queryForList("SELECT grant_id FROM mcp_oauth_token WHERE access_hash = ? OR refresh_hash = ?",
						String.class, tokenHash, tokenHash)
				.stream()
				.findFirst();
			return grantId.flatMap(this::lockGrant)
				.filter(g -> !g.isRevoked() && g.clientId().equals(clientId))
				.map(g -> revoke(g, RevocationReason.CLIENT, now));
		});
	}

	@Override
	public Optional<Grant> revokeGrant(String grantId, String subject, RevocationReason reason, Instant now) {
		if (grantId == null) {
			return Optional.empty();
		}
		return this.tx.execute(s -> lockGrant(grantId)
			.filter(g -> !g.isRevoked() && (subject == null || subject.equals(g.subject())))
			.map(g -> revoke(g, reason, now)));
	}

	@Override
	public List<Grant> revokeAllForSubject(String subject, RevocationReason reason, Instant now) {
		return this.tx.execute(s -> {
			List<Grant> active = this.jdbc.query("SELECT " + GRANT_COLUMNS + " FROM mcp_oauth_grant g "
					+ "WHERE g.subject = ? AND g.revoked_at IS NULL FOR UPDATE", GRANT, subject);
			List<Grant> revoked = new ArrayList<>();
			for (Grant g : active) {
				revoked.add(revoke(g, reason, now));
			}
			return revoked;
		});
	}

	@Override
	public List<Grant> findActiveGrants(String subject) {
		return this.jdbc.query("SELECT " + GRANT_COLUMNS + " FROM mcp_oauth_grant g WHERE g.subject = ? "
				+ "AND g.revoked_at IS NULL ORDER BY g.created_at DESC", GRANT, subject);
	}

	@Override
	public void recordUse(String grantId, String tokenId, Instant now) {
		this.jdbc.update("UPDATE mcp_oauth_token SET first_used_at = ? WHERE token_id = ? AND first_used_at IS NULL",
				param(now), tokenId);
		this.jdbc.update("UPDATE mcp_oauth_grant SET last_used_at = ? WHERE grant_id = ? "
				+ "AND (last_used_at IS NULL OR last_used_at < ?)", param(now), grantId,
				param(now.minus(LAST_USED_RESOLUTION)));
	}

	@Override
	public int purgeExpired(Instant now) {
		Integer removed = this.tx.execute(s -> {
			int n = this.jdbc.update("DELETE FROM mcp_oauth_token WHERE refresh_expires_at <= ?", param(now));
			n += this.jdbc.update("DELETE FROM mcp_oauth_token WHERE grant_id IN (SELECT grant_id FROM mcp_oauth_grant "
					+ "WHERE revoked_at IS NOT NULL AND revoked_at < ?)", param(now.minus(Duration.ofDays(1))));
			n += this.jdbc.update("DELETE FROM mcp_oauth_grant g WHERE NOT EXISTS "
					+ "(SELECT 1 FROM mcp_oauth_token t WHERE t.grant_id = g.grant_id)");
			return n;
		});
		return (removed == null) ? 0 : removed;
	}

	private Optional<Grant> lockGrant(String grantId) {
		return this.jdbc
			.query("SELECT " + GRANT_COLUMNS + " FROM mcp_oauth_grant g WHERE g.grant_id = ? FOR UPDATE", GRANT, grantId)
			.stream()
			.findFirst();
	}

	private Grant revoke(Grant g, RevocationReason reason, Instant now) {
		this.jdbc.update("UPDATE mcp_oauth_grant SET revoked_at = ?, revoked_reason = ? WHERE grant_id = ?", param(now),
				reason.name(), g.grantId());
		return new Grant(g.grantId(), g.subject(), g.clientId(), g.clientName(), g.scopes(), g.resource(), g.createdAt(),
				g.lastUsedAt(), now, reason);
	}

	private static List<String> split(String column) {
		return (column == null || column.isBlank()) ? List.of() : Arrays.asList(column.split(" "));
	}

}
