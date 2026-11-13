// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.peppe_git.mcpauthserver.core.McpEndpoints;
import io.github.peppe_git.mcpauthserver.core.TokenFlow;
import io.github.peppe_git.mcpauthserver.oauth.OAuthException;

/**
 * Token and revocation endpoints. They use no cookie and trust no credential the browser attaches by
 * itself, so they need no CSRF protection; they are protected by what the request carries (code and
 * verifier, refresh token, client identifier).
 */
@RestController
public class TokenController {

	private final TokenFlow flow;

	public TokenController(TokenFlow flow) {
		this.flow = flow;
	}

	@PostMapping(path = McpEndpoints.TOKEN, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<Map<String, Object>> token(@RequestParam MultiValueMap<String, String> form,
			HttpServletRequest request) {
		try {
			rejectQuery(request);
			return OAuthResponses.ok(HttpStatus.OK, this.flow.token(form, hasAuthorization(request)));
		}
		catch (OAuthException ex) {
			return OAuthResponses.error(ex);
		}
	}

	@PostMapping(path = McpEndpoints.REVOKE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<Map<String, Object>> revoke(@RequestParam MultiValueMap<String, String> form,
			HttpServletRequest request) {
		try {
			rejectQuery(request);
			this.flow.revoke(form, hasAuthorization(request));
			return OAuthResponses.ok(HttpStatus.OK, Map.of());
		}
		catch (OAuthException ex) {
			return OAuthResponses.error(ex);
		}
	}

	/** Parameters belong in the body: a query string could leak them to logs and proxies. */
	private static void rejectQuery(HttpServletRequest request) {
		if (request.getQueryString() != null) {
			throw OAuthException.invalidRequest("Parameters must be sent in the request body.");
		}
	}

	private static boolean hasAuthorization(HttpServletRequest request) {
		return request.getHeader(HttpHeaders.AUTHORIZATION) != null;
	}

}
