// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/** Single use and expiry of pending requests and codes, for every {@link AuthorizationStateStore}. */
abstract class AuthorizationStateStoreContract {

	final Instant t0 = Instant.parse("2030-01-01T10:00:00Z");

	AuthorizationStateStore store;

	abstract AuthorizationStateStore newStore();

	@BeforeEach
	void setUp() {
		this.store = newStore();
	}

	@Test
	void aRequestIsTakenOnce() {
		this.store.saveRequest(request("req-1", this.t0.plusSeconds(600)));
		assertThat(this.store.findRequest("req-1", this.t0)).isPresent();
		assertThat(this.store.findRequest("req-1", this.t0)).isPresent();
		PendingAuthorization taken = this.store.takeRequest("req-1", this.t0).orElseThrow();
		assertThat(taken.scopes()).containsExactly("a", "b");
		assertThat(taken.verification()).isEqualTo(ClientVerification.DOMAIN);
		assertThat(this.store.takeRequest("req-1", this.t0)).isEmpty();
		assertThat(this.store.findRequest("req-1", this.t0)).isEmpty();
	}

	@Test
	void anExpiredRequestOrCodeIsGone() {
		this.store.saveRequest(request("req-2", this.t0.plusSeconds(10)));
		this.store.saveCode("hash-2", code(this.t0.plusSeconds(10)));
		assertThat(this.store.findRequest("req-2", this.t0.plusSeconds(10))).isEmpty();
		assertThat(this.store.takeCode("hash-2", this.t0.plusSeconds(11))).isEmpty();
		assertThat(this.store.takeRequest("req-2", this.t0.plusSeconds(11))).isEmpty();
	}

	@Test
	void aCodeIsTakenOnceEvenUnderConcurrency() throws Exception {
		this.store.saveCode("hash-3", code(this.t0.plusSeconds(60)));
		List<Boolean> taken = GrantStoreContract.parallel(8, i -> this.store.takeCode("hash-3", this.t0).isPresent());
		assertThat(taken).filteredOn(b -> b).hasSize(1);
	}

	@Test
	void purgeDeletesExpiredEntries() {
		this.store.saveRequest(request("req-4", this.t0.plusSeconds(10)));
		this.store.saveCode("hash-4", code(this.t0.plusSeconds(10)));
		this.store.saveCode("hash-5", code(this.t0.plusSeconds(100)));
		assertThat(this.store.purgeExpired(this.t0.plusSeconds(20))).isEqualTo(2);
		assertThat(this.store.takeCode("hash-5", this.t0.plusSeconds(20))).isPresent();
	}

	PendingAuthorization request(String id, Instant expiresAt) {
		return new PendingAuthorization(id, "https://client.example/c.json", "Client", ClientVerification.DOMAIN,
				"client.example", "https://client.example/cb", "c".repeat(43), List.of("a", "b"), "xyz",
				"https://mcp.example/mcp", expiresAt);
	}

	IssuedCode code(Instant expiresAt) {
		return new IssuedCode("client", "Client", "https://client.example/cb", "c".repeat(43), List.of("a"),
				"https://mcp.example/mcp", "alice", expiresAt);
	}

}
