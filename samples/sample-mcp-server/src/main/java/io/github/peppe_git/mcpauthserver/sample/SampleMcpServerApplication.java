// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;

/**
 * A minimal MCP server protected by the starter. The application keeps its own login (form login with
 * an in-memory user, for local trials only); the starter adds the OAuth endpoints and protects /mcp.
 */
@SpringBootApplication
public class SampleMcpServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SampleMcpServerApplication.class, args);
	}

	/** The application's own chain: everything else needs a signed-in user. */
	@Bean
	SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(a -> a.requestMatchers("/").permitAll().anyRequest().authenticated())
			.formLogin(Customizer.withDefaults());
		return http.build();
	}

	/** One demo user. Replace with your real user store. */
	@Bean
	InMemoryUserDetailsManager users() {
		return new InMemoryUserDetailsManager(User.withUsername("demo").password("{noop}demo").roles("USER").build());
	}

	/** Audit events: log them, or write them to your audit trail. */
	@EventListener
	void audit(McpAuthorizationEvent event) {
		System.out.println("audit: " + event);
	}

}
