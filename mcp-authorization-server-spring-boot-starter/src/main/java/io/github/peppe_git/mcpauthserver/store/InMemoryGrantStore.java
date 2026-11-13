// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.store.RotationRules.Decision;
import io.github.peppe_git.mcpauthserver.store.RotationRules.Status;

/**
 * {@link GrantStore} for tests and single-instance deployments. One monitor serialises every write,
 * which is the simplest way to honour the per-grant lock. Grants are lost on restart.
 */
public final class InMemoryGrantStore implements GrantStore {

	private static final Duration LAST_USED_RESOLUTION = Duration.ofMinutes(5);

	private static final class TokenRow {

		final String tokenId;

		final String grantId;

		final String accessHash;

		final String refreshHash;

		final Instant createdAt;

		final Instant accessExpiresAt;

		final Instant refreshExpiresAt;

		Status status = Status.ACTIVE;

		Instant endedAt;

		Instant firstUsedAt;

		TokenRow(String grantId, TokenHashes t) {
			this.tokenId = OpaqueTokens.newId();
			this.grantId = grantId;
			this.accessHash = t.accessHash();
			this.refreshHash = t.refreshHash();
			this.createdAt = t.issuedAt();
			this.accessExpiresAt = t.accessExpiresAt();
			this.refreshExpiresAt = t.refreshExpiresAt();
		}

		RotationRules.TokenState state() {
			return new RotationRules.TokenState(this.tokenId, this.createdAt, this.refreshExpiresAt, this.status,
					this.endedAt, this.firstUsedAt);
		}

	}

	private final Object lock = new Object();

	private final Map<String, Grant> grants = new HashMap<>();

	private final Map<String, TokenRow> tokens = new HashMap<>();

	private final Map<String, String> byAccess = new HashMap<>();

	private final Map<String, String> byRefresh = new HashMap<>();

	@Override
	public Grant createGrant(String subject, String clientId, String clientName, List<String> scopes, String resource,
			TokenHashes firstPair) {
		synchronized (this.lock) {
			Grant g = new Grant(OpaqueTokens.newId(), subject, clientId, clientName, scopes, resource,
					firstPair.issuedAt(), null, null, null);
			this.grants.put(g.grantId(), g);
			issue(g.grantId(), firstPair);
			return g;
		}
	}

	private void issue(String grantId, TokenHashes t) {
		TokenRow row = new TokenRow(grantId, t);
		this.tokens.put(row.tokenId, row);
		this.byAccess.put(row.accessHash, row.tokenId);
		this.byRefresh.put(row.refreshHash, row.tokenId);
	}

	@Override
	public Optional<AccessTokenInfo> findActiveAccessToken(String accessHash, Instant now) {
		synchronized (this.lock) {
			TokenRow t = row(this.byAccess.get(accessHash));
			if (t == null || t.status != Status.ACTIVE || !t.accessExpiresAt.isAfter(now)) {
				return Optional.empty();
			}
			Grant g = this.grants.get(t.grantId);
			if (g == null || g.isRevoked()) {
				return Optional.empty();
			}
			return Optional.of(new AccessTokenInfo(g, t.tokenId, t.createdAt, t.accessExpiresAt));
		}
	}

	@Override
	public Rotation rotate(String refreshHash, String clientId, TokenHashes next, RefreshPolicy policy,
			Predicate<String> subjectActive, Function<Grant, String> refuse) {
		synchronized (this.lock) {
			Instant now = next.issuedAt();
			TokenRow presented = row(this.byRefresh.get(refreshHash));
			if (presented == null) {
				return Rotation.invalid("unknown");
			}
			Grant g = this.grants.get(presented.grantId);
			if (g == null) {
				return Rotation.invalid("unknown");
			}
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
			if (!presented.refreshExpiresAt.isAfter(now)) {
				return Rotation.invalid("expired", g, false);
			}
			if (!subjectActive.test(g.subject())) {
				return Rotation.invalid("subject_inactive", revoke(g, RevocationReason.SUBJECT_INACTIVE, now), true);
			}
			List<TokenRow> family = family(g.grantId());
			Decision d = RotationRules.decide(presented.state(), family.stream().map(TokenRow::state).toList(), now,
					policy);
			switch (d.action()) {
				case ROTATE -> {
					presented.status = Status.ROTATED;
					presented.endedAt = now;
					if (presented.firstUsedAt == null) {
						presented.firstUsedAt = now;
					}
					issue(g.grantId(), next);
					return Rotation.rotated(g);
				}
				case SIBLING -> {
					issue(g.grantId(), next);
					return Rotation.rotated(g);
				}
				case RECOVER -> {
					for (String id : d.supersede()) {
						TokenRow s = this.tokens.get(id);
						s.status = Status.SUPERSEDED;
						s.endedAt = now;
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
		}
	}

	@Override
	public Optional<Grant> revokeByToken(String tokenHash, String clientId, Instant now) {
		synchronized (this.lock) {
			String id = this.byAccess.containsKey(tokenHash) ? this.byAccess.get(tokenHash) : this.byRefresh.get(tokenHash);
			TokenRow t = row(id);
			if (t == null) {
				return Optional.empty();
			}
			Grant g = this.grants.get(t.grantId);
			if (g == null || g.isRevoked() || !g.clientId().equals(clientId)) {
				return Optional.empty();
			}
			return Optional.of(revoke(g, RevocationReason.CLIENT, now));
		}
	}

	@Override
	public Optional<Grant> revokeGrant(String grantId, String subject, RevocationReason reason, Instant now) {
		synchronized (this.lock) {
			Grant g = (grantId == null) ? null : this.grants.get(grantId);
			if (g == null || g.isRevoked() || (subject != null && !subject.equals(g.subject()))) {
				return Optional.empty();
			}
			return Optional.of(revoke(g, reason, now));
		}
	}

	@Override
	public List<Grant> revokeAllForSubject(String subject, RevocationReason reason, Instant now) {
		synchronized (this.lock) {
			List<Grant> revoked = new ArrayList<>();
			for (Grant g : List.copyOf(this.grants.values())) {
				if (g.subject().equals(subject) && !g.isRevoked()) {
					revoked.add(revoke(g, reason, now));
				}
			}
			return revoked;
		}
	}

	@Override
	public List<Grant> findActiveGrants(String subject) {
		synchronized (this.lock) {
			return this.grants.values()
				.stream()
				.filter(g -> g.subject().equals(subject) && !g.isRevoked())
				.sorted(Comparator.comparing(Grant::createdAt).reversed())
				.toList();
		}
	}

	@Override
	public void recordUse(String grantId, String tokenId, Instant now) {
		synchronized (this.lock) {
			TokenRow t = this.tokens.get(tokenId);
			if (t != null && t.firstUsedAt == null) {
				t.firstUsedAt = now;
			}
			Grant g = this.grants.get(grantId);
			if (g != null && (g.lastUsedAt() == null || g.lastUsedAt().plus(LAST_USED_RESOLUTION).isBefore(now))) {
				this.grants.put(grantId, new Grant(g.grantId(), g.subject(), g.clientId(), g.clientName(), g.scopes(),
						g.resource(), g.createdAt(), now, g.revokedAt(), g.revokedReason()));
			}
		}
	}

	@Override
	public int purgeExpired(Instant now) {
		synchronized (this.lock) {
			Instant revokedCutoff = now.minus(Duration.ofDays(1));
			int removed = 0;
			for (TokenRow t : List.copyOf(this.tokens.values())) {
				Grant g = this.grants.get(t.grantId);
				boolean deadGrant = g == null || (g.isRevoked() && g.revokedAt().isBefore(revokedCutoff));
				if (!t.refreshExpiresAt.isAfter(now) || deadGrant) {
					this.tokens.remove(t.tokenId);
					this.byAccess.remove(t.accessHash);
					this.byRefresh.remove(t.refreshHash);
					removed++;
				}
			}
			for (Grant g : List.copyOf(this.grants.values())) {
				if (this.tokens.values().stream().noneMatch(t -> t.grantId.equals(g.grantId()))) {
					this.grants.remove(g.grantId());
					removed++;
				}
			}
			return removed;
		}
	}

	private Grant revoke(Grant g, RevocationReason reason, Instant now) {
		Grant revoked = new Grant(g.grantId(), g.subject(), g.clientId(), g.clientName(), g.scopes(), g.resource(),
				g.createdAt(), g.lastUsedAt(), now, reason);
		this.grants.put(g.grantId(), revoked);
		return revoked;
	}

	private List<TokenRow> family(String grantId) {
		return this.tokens.values()
			.stream()
			.filter(t -> t.grantId.equals(grantId))
			.sorted(Comparator.comparing((TokenRow t) -> t.createdAt).thenComparing(t -> t.tokenId))
			.toList();
	}

	private TokenRow row(String tokenId) {
		return (tokenId == null) ? null : this.tokens.get(tokenId);
	}

}
