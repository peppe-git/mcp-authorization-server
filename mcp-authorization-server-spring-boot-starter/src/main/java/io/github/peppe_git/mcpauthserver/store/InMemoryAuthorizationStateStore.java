// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** {@link AuthorizationStateStore} for tests and single-instance deployments. */
public final class InMemoryAuthorizationStateStore implements AuthorizationStateStore {

	private final Map<String, PendingAuthorization> requests = new ConcurrentHashMap<>();

	private final Map<String, IssuedCode> codes = new ConcurrentHashMap<>();

	@Override
	public void saveRequest(PendingAuthorization request) {
		this.requests.put(request.requestId(), request);
	}

	@Override
	public Optional<PendingAuthorization> findRequest(String requestId, Instant now) {
		PendingAuthorization r = (requestId == null) ? null : this.requests.get(requestId);
		return (r == null || !r.expiresAt().isAfter(now)) ? Optional.empty() : Optional.of(r);
	}

	@Override
	public Optional<PendingAuthorization> takeRequest(String requestId, Instant now) {
		PendingAuthorization r = (requestId == null) ? null : this.requests.remove(requestId);
		return (r == null || !r.expiresAt().isAfter(now)) ? Optional.empty() : Optional.of(r);
	}

	@Override
	public void saveCode(String codeHash, IssuedCode code) {
		this.codes.put(codeHash, code);
	}

	@Override
	public Optional<IssuedCode> takeCode(String codeHash, Instant now) {
		IssuedCode c = (codeHash == null) ? null : this.codes.remove(codeHash);
		return (c == null || !c.expiresAt().isAfter(now)) ? Optional.empty() : Optional.of(c);
	}

	@Override
	public int purgeExpired(Instant now) {
		int before = this.requests.size() + this.codes.size();
		this.requests.values().removeIf(r -> !r.expiresAt().isAfter(now));
		this.codes.values().removeIf(c -> !c.expiresAt().isAfter(now));
		return before - this.requests.size() - this.codes.size();
	}

}
