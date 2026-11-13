// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.autoconfigure;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.SmartLifecycle;

import io.github.peppe_git.mcpauthserver.store.AuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.GrantStore;

/** Deletes expired requests, codes and token pairs at a fixed interval, on one daemon thread. */
public final class McpStoreMaintenance implements SmartLifecycle {

	private static final Log logger = LogFactory.getLog(McpStoreMaintenance.class);

	private final AuthorizationStateStore state;

	private final GrantStore grants;

	private final Clock clock;

	private final Duration interval;

	private ScheduledExecutorService executor;

	public McpStoreMaintenance(AuthorizationStateStore state, GrantStore grants, Clock clock, Duration interval) {
		this.state = state;
		this.grants = grants;
		this.clock = clock;
		this.interval = interval;
	}

	/** Runs one purge now; returns the number of deleted entries. */
	public int purge() {
		Instant now = Instant.now(this.clock);
		return this.state.purgeExpired(now) + this.grants.purgeExpired(now);
	}

	@Override
	public synchronized void start() {
		this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "mcp-authorization-server-maintenance");
			t.setDaemon(true);
			return t;
		});
		long millis = Math.max(1000, this.interval.toMillis());
		this.executor.scheduleWithFixedDelay(() -> {
			try {
				int n = purge();
				if (n > 0 && logger.isDebugEnabled()) {
					logger.debug("Purged " + n + " expired authorization entries");
				}
			}
			catch (RuntimeException ex) {
				logger.warn("Purge of expired authorization entries failed", ex);
			}
		}, millis, millis, TimeUnit.MILLISECONDS);
	}

	@Override
	public synchronized void stop() {
		if (this.executor != null) {
			this.executor.shutdownNow();
			this.executor = null;
		}
	}

	@Override
	public synchronized boolean isRunning() {
		return this.executor != null;
	}

}
