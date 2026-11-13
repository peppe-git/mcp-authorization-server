// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.sample;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.peppe_git.mcpauthserver.oauth.Pkce;

/** The sample, end to end, as the quickstart guide describes it. */
@SpringBootTest
@AutoConfigureMockMvc
class SampleMcpServerApplicationTest {

	static final String VERIFIER = "sample-verifier-0123456789-0123456789-0123456789";

	@Autowired
	MockMvc mvc;

	@Test
	void quickstart() throws Exception {
		this.mvc.perform(post("/mcp").contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string("WWW-Authenticate", Matchers.containsString(
					"resource_metadata=\"http://localhost:8080/.well-known/oauth-protected-resource/mcp\"")));
		this.mvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(jsonPath("$.issuer").value("http://localhost:8080"));
		// The application's own chain still guards its other routes.
		this.mvc.perform(get("/private")).andExpect(redirectedUrl("/login"));

		MockHttpSession session = new MockHttpSession();
		String location = this.mvc.perform(get("/oauth2/authorize").session(session)
			.param("response_type", "code")
			.param("client_id", "sample-cli")
			.param("redirect_uri", "http://127.0.0.1:8765/callback")
			.param("code_challenge", Pkce.s256(VERIFIER))
			.param("code_challenge_method", "S256")
			.param("resource", "http://localhost:8080/mcp")
			.param("state", "s")).andReturn().getResponse().getHeader("Location");
		String requestId = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("request_id");
		String back = this.mvc.perform(post("/oauth2/consent").session(session)
			.with(user("demo"))
			.with(csrf())
			.param("request_id", requestId)
			.param("decision", "approve")).andReturn().getResponse().getHeader("Location");
		String code = UriComponentsBuilder.fromUriString(back).build().getQueryParams().getFirst("code");
		String body = this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param("grant_type", "authorization_code")
			.param("client_id", "sample-cli")
			.param("code", code)
			.param("code_verifier", VERIFIER)
			.param("redirect_uri", "http://127.0.0.1:8765/callback")).andReturn().getResponse().getContentAsString();
		Map<String, Object> tokens = JsonParserFactory.getJsonParser().parseMap(body);
		this.mvc.perform(post("/mcp").header("Authorization", "Bearer " + tokens.get("access_token"))
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.result.subject").value("demo"))
			.andExpect(jsonPath("$.result.scopes[0]").value("tools.read"));
	}

}
