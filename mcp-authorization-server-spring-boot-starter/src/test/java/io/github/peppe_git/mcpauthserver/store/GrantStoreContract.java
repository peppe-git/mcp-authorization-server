// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.store.Rotation.Outcome;

/**
 * The behaviour every {@link GrantStore} must have: rotation, sibling grace, lost-response recovery,
 * reuse detection and revocation (ADR-0004). Run against each implementation.
 */
abstract class GrantStoreContract {

	static final RefreshPolicy GRACE = new RefreshPolicy(Duration.ofSeconds(30), Duration.ofMinutes(10));

	static final String CLIENT = "client-1";

	final Instant t0 = Instant.parse("2030-01-01T10:00:00Z");

	GrantStore store;

	Grant grant;

	abstract GrantStore newStore();

	@BeforeEach
	void setUp() {
		this.store = newStore();
		this.grant = this.store.createGrant("alice", CLIENT, "Client One", List.of("tools.read"),
				"https://mcp.example/mcp", pair("r0", this.t0));
	}

	@Test
	void anActiveTokenRotatesAndItsAccessTokenStopsWorking() {
		Rotation r = rotate("r0", "r1", this.t0.plus(1, ChronoUnit.HOURS).minusSeconds(60));
		assertThat(r.outcome()).isEqualTo(Outcome.ROTATED);
		assertThat(r.grant().grantId()).isEqualTo(this.grant.grantId());
		Instant now = this.t0.plusSeconds(30 * 60 + 60);
		assertThat(this.store.findActiveAccessToken(hash("a-r0"), now)).isEmpty();
		assertThat(this.store.findActiveAccessToken(hash("a-r1"), now)).isPresent();
	}

	@Test
	void concurrentRefreshesWithinTheGraceAllSucceed() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		assertThat(rotate("r0", "r1", t).outcome()).isEqualTo(Outcome.ROTATED);
		assertThat(rotate("r0", "r2", t.plusSeconds(2)).outcome()).isEqualTo(Outcome.ROTATED);
		// Both responses carry usable pairs.
		assertThat(this.store.findActiveAccessToken(hash("a-r1"), t.plusSeconds(3))).isPresent();
		assertThat(this.store.findActiveAccessToken(hash("a-r2"), t.plusSeconds(3))).isPresent();
		assertThat(rotate("r1", "r3", t.plusSeconds(4)).outcome()).isEqualTo(Outcome.ROTATED);
		assertThat(rotate("r2", "r4", t.plusSeconds(5)).outcome()).isEqualTo(Outcome.ROTATED);
	}

	@Test
	void aLostResponseIsRecoveredOnceIfTheSuccessorWasNeverUsed() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		rotate("r0", "r1", t);
		assertThat(rotate("r0", "r2", t.plus(5, ChronoUnit.MINUTES)).outcome()).isEqualTo(Outcome.ROTATED);
		// r1 was superseded: presenting it now is reuse.
		assertThat(rotate("r1", "r3", t.plus(6, ChronoUnit.MINUTES)).outcome()).isEqualTo(Outcome.REUSE_DETECTED);
	}

	@Test
	void theLostResponseRecoveryWorksOnlyOnce() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		rotate("r0", "r1", t);
		assertThat(rotate("r0", "r2", t.plus(5, ChronoUnit.MINUTES)).outcome()).isEqualTo(Outcome.ROTATED);
		Rotation third = rotate("r0", "r3", t.plus(6, ChronoUnit.MINUTES));
		assertThat(third.outcome()).isEqualTo(Outcome.REUSE_DETECTED);
		assertThat(third.grant().revokedReason()).isEqualTo(RevocationReason.REFRESH_TOKEN_REUSE);
	}

	@Test
	void ifTheSuccessorWasUsedTheOldTokenIsReuse() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		rotate("r0", "r1", t);
		AccessTokenInfo a1 = this.store.findActiveAccessToken(hash("a-r1"), t.plusSeconds(60)).orElseThrow();
		this.store.recordUse(a1.grant().grantId(), a1.tokenId(), t.plusSeconds(60));
		assertThat(rotate("r0", "r2", t.plus(5, ChronoUnit.MINUTES)).outcome()).isEqualTo(Outcome.REUSE_DETECTED);
		assertThat(this.store.findActiveAccessToken(hash("a-r1"), t.plus(5, ChronoUnit.MINUTES))).isEmpty();
	}

	@Test
	void beyondBothWindowsReuseRevokesTheWholeGrant() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		rotate("r0", "r1", t);
		Rotation r = rotate("r0", "r2", t.plus(11, ChronoUnit.MINUTES));
		assertThat(r.outcome()).isEqualTo(Outcome.REUSE_DETECTED);
		assertThat(r.revokedNow()).isTrue();
		// Every token of the family is dead, including the legitimate successor.
		assertThat(this.store.findActiveAccessToken(hash("a-r1"), t.plus(12, ChronoUnit.MINUTES))).isEmpty();
		assertThat(rotate("r1", "r3", t.plus(12, ChronoUnit.MINUTES)).reason()).isEqualTo("revoked");
		assertThat(this.store.findActiveGrants("alice")).isEmpty();
	}

	@Test
	void withoutGraceAnyReplayIsReuse() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		this.store.rotate(hash("r0"), CLIENT, pair("r1", t), RefreshPolicy.STRICT, s -> true, g -> null);
		Rotation r = this.store.rotate(hash("r0"), CLIENT, pair("r2", t.plusSeconds(1)), RefreshPolicy.STRICT,
				s -> true, g -> null);
		assertThat(r.outcome()).isEqualTo(Outcome.REUSE_DETECTED);
	}

	@Test
	void refusalsCarryTheirReasonAndChangeNothing() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		assertThat(this.store.rotate(hash("r0"), "other-client", pair("x1", t), GRACE, s -> true, g -> null).reason())
			.isEqualTo("wrong_client");
		assertThat(this.store.rotate(hash("r0"), CLIENT, pair("x2", t), GRACE, s -> true, g -> "invalid_scope").reason())
			.isEqualTo("invalid_scope");
		assertThat(rotate("unknown", "x3", t).reason()).isEqualTo("unknown");
		assertThat(rotate("r0", "x4", this.t0.plus(31, ChronoUnit.DAYS)).reason()).isEqualTo("expired");
		// Still active after all the refusals.
		assertThat(rotate("r0", "r1", t).outcome()).isEqualTo(Outcome.ROTATED);
	}

	@Test
	void anInactiveSubjectLosesTheGrantOnRefresh() {
		Rotation r = this.store.rotate(hash("r0"), CLIENT, pair("r1", this.t0.plusSeconds(60)), GRACE, s -> false,
				g -> null);
		assertThat(r.outcome()).isEqualTo(Outcome.INVALID);
		assertThat(r.reason()).isEqualTo("subject_inactive");
		assertThat(r.revokedNow()).isTrue();
		assertThat(this.store.findActiveGrants("alice")).isEmpty();
	}

	@Test
	void theClientRevokesWithAnyTokenOfTheFamily() {
		Instant t = this.t0.plus(1, ChronoUnit.HOURS);
		rotate("r0", "r1", t);
		// Another client cannot revoke it.
		assertThat(this.store.revokeByToken(hash("r0"), "other-client", t)).isEmpty();
		// The already rotated refresh token still identifies the grant.
		assertThat(this.store.revokeByToken(hash("r0"), CLIENT, t)).isPresent();
		assertThat(this.store.findActiveAccessToken(hash("a-r1"), t.plusSeconds(1))).isEmpty();
		assertThat(this.store.revokeByToken(hash("a-r1"), CLIENT, t)).isEmpty();
	}

	@Test
	void userAndAdministrativeRevocation() {
		Grant second = this.store.createGrant("alice", "client-2", "Client Two", List.of(), "https://mcp.example/mcp",
				pair("s0", this.t0.plusSeconds(1)));
		this.store.createGrant("bob", CLIENT, "Client One", List.of(), "https://mcp.example/mcp",
				pair("b0", this.t0.plusSeconds(2)));
		assertThat(this.store.findActiveGrants("alice")).extracting(Grant::grantId)
			.containsExactly(second.grantId(), this.grant.grantId());
		// Bob cannot revoke Alice's grant.
		assertThat(this.store.revokeGrant(this.grant.grantId(), "bob", RevocationReason.USER, this.t0)).isEmpty();
		assertThat(this.store.revokeGrant(this.grant.grantId(), "alice", RevocationReason.USER, this.t0)).isPresent();
		assertThat(this.store.revokeAllForSubject("alice", RevocationReason.ADMINISTRATIVE, this.t0)).hasSize(1);
		assertThat(this.store.findActiveGrants("alice")).isEmpty();
		assertThat(this.store.findActiveGrants("bob")).hasSize(1);
	}

	@Test
	void purgeRemovesExpiredPairsAndEmptyGrants() {
		Instant later = this.t0.plus(31, ChronoUnit.DAYS);
		assertThat(this.store.purgeExpired(later)).isGreaterThanOrEqualTo(2);
		assertThat(rotate("r0", "r1", later).reason()).isEqualTo("unknown");
		assertThat(this.store.findActiveGrants("alice")).isEmpty();
	}

	@Test
	void parallelRefreshesOfOneTokenNeverRaceWithGrace() throws Exception {
		List<Rotation> results = parallel(8, i -> this.store.rotate(hash("r0"), CLIENT,
				pair("p" + i, this.t0.plusSeconds(100)), GRACE, s -> true, g -> null));
		assertThat(results).allMatch(r -> r.outcome() == Outcome.ROTATED);
		assertThat(this.store.findActiveGrants("alice")).hasSize(1);
	}

	@Test
	void parallelRefreshesOfOneTokenWithoutGraceRotateExactlyOnce() throws Exception {
		List<Rotation> results = parallel(8, i -> this.store.rotate(hash("r0"), CLIENT,
				pair("q" + i, this.t0.plusSeconds(100)), RefreshPolicy.STRICT, s -> true, g -> null));
		assertThat(results).filteredOn(r -> r.outcome() == Outcome.ROTATED).hasSize(1);
		assertThat(results).filteredOn(r -> r.outcome() == Outcome.REUSE_DETECTED).hasSize(1);
		assertThat(this.store.findActiveGrants("alice")).isEmpty();
	}

	interface IndexedCall<T> {

		T call(int i) throws Exception;

	}

	static <T> List<T> parallel(int n, IndexedCall<T> call) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(n);
		try {
			CountDownLatch start = new CountDownLatch(1);
			List<Future<T>> futures = new ArrayList<>();
			for (int i = 0; i < n; i++) {
				int index = i;
				Callable<T> task = () -> {
					start.await();
					return call.call(index);
				};
				futures.add(pool.submit(task));
			}
			start.countDown();
			List<T> results = new ArrayList<>();
			for (Future<T> f : futures) {
				results.add(f.get());
			}
			return results;
		}
		finally {
			pool.shutdownNow();
		}
	}

	Rotation rotate(String presented, String next, Instant at) {
		return this.store.rotate(hash(presented), CLIENT, pair(next, at), GRACE, s -> true, g -> null);
	}

	static TokenHashes pair(String refresh, Instant at) {
		return new TokenHashes(hash("a-" + refresh), hash(refresh), at, at.plus(Duration.ofHours(1)),
				at.plus(Duration.ofDays(30)));
	}

	static String hash(String value) {
		return OpaqueTokens.hash(value);
	}

}
