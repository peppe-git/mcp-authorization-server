// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.peppe_git.mcpauthserver.core.McpEndpoints;
import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.oauth.Pkce;

/**
 * Discovery documents: protected resource metadata (RFC 9728) and authorization server metadata
 * (RFC 8414). Both are built from configuration, never from request headers, so a forged
 * {@code Host} cannot change them.
 */
@RestController
public class MetadataController {

	private final McpServerSettings settings;

	public MetadataController(McpServerSettings settings) {
		this.settings = settings;
	}

	@GetMapping({ McpEndpoints.PROTECTED_RESOURCE_METADATA, McpEndpoints.PROTECTED_RESOURCE_METADATA + "/**" })
	public ResponseEntity<Map<String, Object>> protectedResource(HttpServletRequest request) {
		String suffix = suffix(request, McpEndpoints.PROTECTED_RESOURCE_METADATA);
		if (!suffix.isEmpty() && !suffix.equals(this.settings.resourcePath())) {
			return ResponseEntity.notFound().build();
		}
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("resource", this.settings.resource());
		m.put("authorization_servers", List.of(this.settings.issuer()));
		m.put("scopes_supported", this.settings.scopes().supported());
		m.put("bearer_methods_supported", List.of("header"));
		if (this.settings.resourceName() != null && !this.settings.resourceName().isBlank()) {
			m.put("resource_name", this.settings.resourceName());
		}
		return cached(m);
	}

	@GetMapping({ McpEndpoints.AUTHORIZATION_SERVER_METADATA, McpEndpoints.AUTHORIZATION_SERVER_METADATA + "/**" })
	public ResponseEntity<Map<String, Object>> authorizationServer(HttpServletRequest request) {
		String suffix = suffix(request, McpEndpoints.AUTHORIZATION_SERVER_METADATA);
		if (!suffix.isEmpty() && !suffix.equals(this.settings.issuerPath())) {
			return ResponseEntity.notFound().build();
		}
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("issuer", this.settings.issuer());
		m.put("authorization_endpoint", this.settings.authorizationEndpoint());
		m.put("token_endpoint", this.settings.tokenEndpoint());
		m.put("revocation_endpoint", this.settings.revocationEndpoint());
		if (this.settings.dcrEnabled()) {
			m.put("registration_endpoint", this.settings.registrationEndpoint());
		}
		m.put("scopes_supported", this.settings.scopes().supported());
		m.put("response_types_supported", List.of("code"));
		m.put("response_modes_supported", List.of("query"));
		m.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
		m.put("code_challenge_methods_supported", List.of(Pkce.S256));
		m.put("token_endpoint_auth_methods_supported", List.of("none"));
		m.put("revocation_endpoint_auth_methods_supported", List.of("none"));
		m.put("authorization_response_iss_parameter_supported", true);
		if (this.settings.cimdEnabled()) {
			m.put("client_id_metadata_document_supported", true);
		}
		return cached(m);
	}

	private static String suffix(HttpServletRequest request, String prefix) {
		String path = request.getRequestURI().substring(request.getContextPath().length());
		return path.length() > prefix.length() ? path.substring(prefix.length()) : "";
	}

	private static ResponseEntity<Map<String, Object>> cached(Map<String, Object> body) {
		return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic()).body(body);
	}

}
