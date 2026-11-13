// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.Map;

import org.springframework.boot.json.JsonParserFactory;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.oauth.Pkce;

/** Plays the part of an MCP client and of the user's browser against MockMvc. */
final class OAuthClientSimulator {

	static final String RESOURCE = "http://localhost/mcp";

	final MockMvc mvc;

	final MockHttpSession session = new MockHttpSession();

	String verifier = OpaqueTokens.random() + "-v";

	OAuthClientSimulator(MockMvc mvc) {
		this.mvc = mvc;
	}

	MultiValueMap<String, String> authorizeParams(String clientId, String redirectUri) {
		MultiValueMap<String, String> p = new LinkedMultiValueMap<>();
		p.add("response_type", "code");
		p.add("client_id", clientId);
		p.add("redirect_uri", redirectUri);
		p.add("code_challenge", Pkce.s256(this.verifier));
		p.add("code_challenge_method", "S256");
		p.add("state", "state-123");
		p.add("resource", RESOURCE);
		p.add("scope", "tools.read offline_access");
		return p;
	}

	MockHttpServletResponse authorize(MultiValueMap<String, String> params) throws Exception {
		return this.mvc.perform(get("/oauth2/authorize").params(params).session(this.session)).andReturn().getResponse();
	}

	/** The pending request id from the authorize redirect to the consent page. */
	static String requestId(MockHttpServletResponse authorizeResponse) {
		return query(authorizeResponse.getHeader("Location")).getFirst("request_id");
	}

	ResultActions consentPage(String requestId, String username) throws Exception {
		return this.mvc.perform(get("/oauth2/consent").param("request_id", requestId).session(this.session)
			.with(user(username)));
	}

	MockHttpServletResponse decide(String requestId, String username, String decision) throws Exception {
		return this.mvc.perform(post("/oauth2/consent").param("request_id", requestId).param("decision", decision)
			.session(this.session)
			.with(user(username))
			.with(csrf())).andReturn().getResponse();
	}

	/** Authorize, approve and return the authorization code. */
	String code(String clientId, String redirectUri, String username) throws Exception {
		String requestId = requestId(authorize(authorizeParams(clientId, redirectUri)));
		MockHttpServletResponse decided = decide(requestId, username, "approve");
		return query(decided.getHeader("Location")).getFirst("code");
	}

	ResultActions token(Map<String, String> form) throws Exception {
		var request = post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED);
		form.forEach(request::param);
		return this.mvc.perform(request);
	}

	ResultActions exchange(String clientId, String code, String verifier, String redirectUri) throws Exception {
		return token(Map.of("grant_type", "authorization_code", "client_id", clientId, "code", code, "code_verifier",
				verifier, "redirect_uri", redirectUri, "resource", RESOURCE));
	}

	/** Full flow up to the token response, as a map. */
	Map<String, Object> tokens(String clientId, String redirectUri, String username) throws Exception {
		String code = code(clientId, redirectUri, username);
		return json(exchange(clientId, code, this.verifier, redirectUri).andReturn().getResponse().getContentAsString());
	}

	ResultActions refresh(String clientId, String refreshToken) throws Exception {
		return token(Map.of("grant_type", "refresh_token", "client_id", clientId, "refresh_token", refreshToken));
	}

	ResultActions callMcp(String accessToken) throws Exception {
		return this.mvc.perform(post("/mcp").header("Authorization", "Bearer " + accessToken)
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
	}

	static MultiValueMap<String, String> query(String location) {
		return UriComponentsBuilder.fromUriString(location).build().getQueryParams();
	}

	static Map<String, Object> json(String body) {
		return JsonParserFactory.getJsonParser().parseMap(body);
	}

}
