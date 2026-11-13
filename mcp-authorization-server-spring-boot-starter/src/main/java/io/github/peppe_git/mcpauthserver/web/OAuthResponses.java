// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import io.github.peppe_git.mcpauthserver.oauth.OAuthException;

/** JSON responses of the OAuth endpoints: never cached (RFC 6749 §5.1). */
final class OAuthResponses {

	private OAuthResponses() {
	}

	static ResponseEntity<Map<String, Object>> ok(HttpStatus status, Map<String, Object> body) {
		return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).header("Pragma", "no-cache").body(body);
	}

	static ResponseEntity<Map<String, Object>> error(OAuthException ex) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("error", ex.error());
		if (ex.getMessage() != null) {
			body.put("error_description", ex.getMessage());
		}
		return ok(HttpStatus.valueOf(ex.status()), body);
	}

}
