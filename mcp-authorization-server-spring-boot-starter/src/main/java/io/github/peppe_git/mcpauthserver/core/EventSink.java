// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;

/**
 * Publishes audit events. A failing listener is logged and never changes the OAuth response: the
 * security decision (a revocation, a refusal) has already been taken and stored.
 */
public final class EventSink implements Consumer<McpAuthorizationEvent> {

	private static final Log logger = LogFactory.getLog(EventSink.class);

	private final Consumer<Object> publisher;

	public EventSink(Consumer<Object> publisher) {
		this.publisher = publisher;
	}

	@Override
	public void accept(McpAuthorizationEvent event) {
		try {
			this.publisher.accept(event);
		}
		catch (RuntimeException ex) {
			logger.warn("Audit event listener failed for " + event.getClass().getSimpleName(), ex);
		}
	}

}
