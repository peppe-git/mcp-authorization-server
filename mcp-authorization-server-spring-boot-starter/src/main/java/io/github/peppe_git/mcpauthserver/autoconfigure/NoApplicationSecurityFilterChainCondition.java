// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.autoconfigure;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Matches when no security filter chain exists besides the starter's own. The starter's chains only
 * cover the OAuth endpoints and the MCP path; without this fallback, registering them would switch off
 * Spring Boot's default chain and leave every other route of the application unprotected.
 */
class NoApplicationSecurityFilterChainCondition extends SpringBootCondition implements ConfigurationCondition {

	static final Set<String> OWN_CHAINS = Set.of(McpAuthorizationServerSecurityConfiguration.AUTHORIZATION_SERVER_CHAIN,
			McpAuthorizationServerSecurityConfiguration.RESOURCE_SERVER_CHAIN,
			McpAuthorizationServerSecurityConfiguration.FALLBACK_CHAIN);

	@Override
	public ConfigurationPhase getConfigurationPhase() {
		return ConfigurationPhase.REGISTER_BEAN;
	}

	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
		ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
		List<String> others = Arrays.stream(beanFactory.getBeanNamesForType(SecurityFilterChain.class, true, false))
			.filter(name -> !OWN_CHAINS.contains(name))
			.toList();
		return others.isEmpty() ? ConditionOutcome.match("no application security filter chain")
				: ConditionOutcome.noMatch("application security filter chains: " + others);
	}

}
