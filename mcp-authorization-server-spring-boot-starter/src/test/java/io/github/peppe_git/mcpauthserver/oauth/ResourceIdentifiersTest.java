// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ResourceIdentifiersTest {

	@Test
	void canonicalForm() {
		assertThat(ResourceIdentifiers.canonical("HTTPS://MCP.Example.com:443/mcp/")).contains("https://mcp.example.com/mcp");
		assertThat(ResourceIdentifiers.same("https://mcp.example.com/mcp", "https://mcp.example.com/mcp/")).isTrue();
		assertThat(ResourceIdentifiers.same("https://mcp.example.com/mcp", "https://mcp.example.com/other")).isFalse();
		assertThat(ResourceIdentifiers.same("https://mcp.example.com/mcp", "https://mcp.example.com:8443/mcp")).isFalse();
		assertThat(ResourceIdentifiers.canonical("https://mcp.example.com/mcp#f")).isEmpty();
		assertThat(ResourceIdentifiers.canonical("urn:x")).isEmpty();
		assertThat(ResourceIdentifiers.same(null, null)).isFalse();
	}

}
