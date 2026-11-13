// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.sample;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * A stand-in for a real MCP endpoint, just enough to see the authorization work. A real server uses the
 * MCP Java SDK or Spring AI MCP on the same path; the starter does not care what answers behind it.
 */
@RestController
class ToyMcpController {

	@PostMapping("/mcp")
	Map<String, Object> mcp(@RequestBody Map<String, Object> request, Authentication authentication) {
		Object id = request.get("id");
		Object method = request.get("method");
		Object result = "tools/list".equals(method)
				? Map.of("tools", List.of(Map.of("name", "whoami", "description", "Who is calling")))
				: Map.of("subject", authentication.getName(), "scopes", scopes(authentication));
		return Map.of("jsonrpc", "2.0", "id", id == null ? 0 : id, "result", result);
	}

	@GetMapping("/")
	String home() {
		return "Sample MCP server. Discovery: /.well-known/oauth-protected-resource/mcp";
	}

	private static List<String> scopes(Authentication authentication) {
		return authentication.getAuthorities()
			.stream()
			.map(a -> a.getAuthority())
			.filter(a -> a.startsWith("SCOPE_"))
			.map(a -> a.substring("SCOPE_".length()))
			.toList();
	}

}
