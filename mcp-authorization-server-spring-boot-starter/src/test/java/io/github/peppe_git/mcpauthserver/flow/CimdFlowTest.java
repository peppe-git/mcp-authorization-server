// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import io.github.peppe_git.mcpauthserver.cimd.MetadataDocumentFetcher;
import io.github.peppe_git.mcpauthserver.cimd.TestFetchers;
import io.github.peppe_git.mcpauthserver.cimd.TestTls;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;

/**
 * A client identified by a Client ID Metadata Document, served over TLS by a local server that the
 * fetcher reaches through the real address policy (only the final connection is redirected).
 */
@SpringBootTest(classes = { TestMcpApplication.class, CimdFlowTest.LocalMetadataServer.class })
@AutoConfigureMockMvc
class CimdFlowTest {

	static final String CLIENT_ID = "https://cimd.test/client.json";

	static final String IMPOSTOR_ID = "https://cimd.test/impostor.json";

	static final String REDIRECT = "https://cimd.test/callback";

	static final TestTls.Server SERVER;

	static {
		try {
			SERVER = new TestTls.Server((head, out) -> {
				String body = head.startsWith("GET /client.json ")
						? "{\"client_id\":\"" + CLIENT_ID + "\",\"client_name\":\"Metadata Client\",\"redirect_uris\":[\""
								+ REDIRECT + "\",\"http://localhost/callback\"]}"
						: "{\"client_id\":\"https://cimd.test/client.json\",\"redirect_uris\":[\"https://evil.example/cb\"]}";
				byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
				out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=300\r\n"
						+ "Content-Length: " + bytes.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
				out.write(bytes);
				out.flush();
			});
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	@TestConfiguration
	static class LocalMetadataServer {

		@Bean
		MetadataDocumentFetcher localMetadataDocumentFetcher() throws Exception {
			return TestFetchers.toLocalServer(SERVER);
		}

	}

	@AfterAll
	static void stop() throws Exception {
		SERVER.close();
	}

	@Autowired
	MockMvc mvc;

	@Autowired
	TestMcpApplication.Events events;

	@Test
	void aMetadataDocumentClientCompletesTheFlowAndShowsItsVerifiedDomain() throws Exception {
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		MockHttpServletResponse authorize = client.authorize(client.authorizeParams(CLIENT_ID, REDIRECT));
		assertThat(authorize.getStatus()).isEqualTo(302);
		String requestId = OAuthClientSimulator.requestId(authorize);
		client.consentPage(requestId, "alice")
			.andExpect(status().isOk())
			.andExpect(content().string(Matchers.containsString("Metadata Client")))
			.andExpect(content().string(Matchers.containsString("Published by <strong>cimd.test</strong>")));
		String code = OAuthClientSimulator.query(client.decide(requestId, "alice", "approve").getHeader("Location"))
			.getFirst("code");
		Map<String, Object> tokens = OAuthClientSimulator.json(client.exchange(CLIENT_ID, code, client.verifier, REDIRECT)
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString());
		client.callMcp((String) tokens.get("access_token")).andExpect(jsonPath("$.sub").value("alice"));
		client.refresh(CLIENT_ID, (String) tokens.get("refresh_token")).andExpect(status().isOk());

		// The document is cached: a second authorization does not fetch it again.
		int fetches = SERVER.requests().size();
		client.authorize(client.authorizeParams(CLIENT_ID, "http://localhost:4567/callback"));
		assertThat(SERVER.requests()).hasSize(fetches);
	}

	@Test
	void aDocumentThatClaimsAnotherClientIdIsRefused() throws Exception {
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		MockHttpServletResponse r = client.authorize(client.authorizeParams(IMPOSTOR_ID, "https://evil.example/cb"));
		assertThat(r.getStatus()).isEqualTo(400);
		assertThat(r.getHeader("Location")).isNull();
		assertThat(this.events.received).anySatisfy(e -> assertThat(e)
			.isInstanceOfSatisfying(McpAuthorizationEvent.ClientMetadataRejected.class,
					rejected -> assertThat(rejected.reason()).contains("differs")));
	}

	@Test
	void aRedirectNotInTheDocumentIsRefused() throws Exception {
		OAuthClientSimulator client = new OAuthClientSimulator(this.mvc);
		MockHttpServletResponse r = client.authorize(client.authorizeParams(CLIENT_ID, "https://cimd.test/other"));
		assertThat(r.getStatus()).isEqualTo(400);
		assertThat(r.getHeader("Location")).isNull();
	}

}
