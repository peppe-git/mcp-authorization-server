// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;

/** A minimal application: an "MCP" endpoint, another protected route, two users. */
@SpringBootApplication
public class TestMcpApplication {

	@Bean
	InMemoryUserDetailsManager users() {
		return new InMemoryUserDetailsManager(User.withUsername("alice").password("{noop}alice-password").roles("USER").build(),
				User.withUsername("bob").password("{noop}bob-password").roles("USER").build());
	}

	@Bean
	MutableClock clock() {
		return new MutableClock();
	}

	@RestController
	static class Endpoints {

		@PostMapping({ "/mcp", "/mcp/" })
		Map<String, Object> mcp(Authentication authentication) {
			return Map.of("sub", authentication.getName(), "authorities",
					authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
		}

		@GetMapping("/hello")
		String hello() {
			return "hello";
		}

	}

	/** Collects every audit event. */
	@Component
	public static class Events {

		public final List<McpAuthorizationEvent> received = new CopyOnWriteArrayList<>();

		@EventListener
		void on(McpAuthorizationEvent event) {
			this.received.add(event);
		}

	}

	/** A clock the tests can move forward. */
	public static class MutableClock extends Clock {

		private volatile Instant now = Instant.now();

		public void advance(Duration d) {
			this.now = this.now.plus(d);
		}

		@Override
		public ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return this.now;
		}

	}

}
