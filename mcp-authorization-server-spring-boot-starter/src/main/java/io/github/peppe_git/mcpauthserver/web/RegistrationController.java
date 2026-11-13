// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.util.Map;

import org.springframework.boot.json.JsonParserFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.github.peppe_git.mcpauthserver.client.DynamicClientRegistration;
import io.github.peppe_git.mcpauthserver.core.McpEndpoints;
import io.github.peppe_git.mcpauthserver.oauth.OAuthException;

/** RFC 7591 registration endpoint. Only registered as a bean when dynamic registration is enabled. */
@RestController
public class RegistrationController {

	private static final int MAX_BODY_CHARS = 16 * 1024;

	private final DynamicClientRegistration registration;

	public RegistrationController(DynamicClientRegistration registration) {
		this.registration = registration;
	}

	@PostMapping(path = McpEndpoints.REGISTER, consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, Object>> register(@RequestBody String body) {
		try {
			if (body.length() > MAX_BODY_CHARS) {
				throw new OAuthException("invalid_client_metadata", "The registration request is too large.", 400);
			}
			Map<String, Object> request;
			try {
				request = JsonParserFactory.getJsonParser().parseMap(body);
			}
			catch (IllegalArgumentException | ClassCastException ex) {
				throw new OAuthException("invalid_client_metadata", "The request body must be a JSON object.", 400);
			}
			return OAuthResponses.ok(HttpStatus.CREATED, this.registration.register(request));
		}
		catch (OAuthException ex) {
			return OAuthResponses.error(ex);
		}
	}

}
