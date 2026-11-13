// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import io.github.peppe_git.mcpauthserver.oauth.Pkce;

/**
 * The flow on a real embedded Tomcat with a real browser-like client: the application's form login,
 * the saved request back to the consent page, cookies, CSRF fields parsed from HTML, and error
 * responses that go through the container's error dispatch.
 */
@SpringBootTest(classes = TestMcpApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = { "mcp.authorization-server.issuer=http://localhost", "mcp.authorization-server.resource=http://localhost/mcp" })
class RealServerTest {

	static final String VERIFIER = "real-server-verifier-0123456789-0123456789-0123456789";

	static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"");

	@LocalServerPort
	int port;

	final HttpClient browser = HttpClient.newBuilder()
		.cookieHandler(new CookieManager())
		.followRedirects(HttpClient.Redirect.NEVER)
		.build();

	@Test
	void signInThroughTheApplicationLoginThenConsentThenCallMcp() throws Exception {
		HttpResponse<String> authorize = get("/oauth2/authorize?response_type=code&client_id=test-cli"
				+ "&redirect_uri=" + enc("http://127.0.0.1:8765/callback") + "&code_challenge=" + Pkce.s256(VERIFIER)
				+ "&code_challenge_method=S256&state=xyz");
		assertThat(authorize.statusCode()).isEqualTo(302);
		String consentPath = location(authorize);
		assertThat(consentPath).startsWith("/oauth2/consent?request_id=");

		HttpResponse<String> toLogin = get(consentPath);
		assertThat(toLogin.statusCode()).isEqualTo(302);
		assertThat(location(toLogin)).endsWith("/login");

		HttpResponse<String> loginPage = get("/login");
		HttpResponse<String> login = postForm("/login",
				Map.of("username", "alice", "password", "alice-password", "_csrf", csrf(loginPage.body())));
		assertThat(login.statusCode()).isEqualTo(302);
		// The saved request brings the user back to the consent page.
		String back = location(login);
		assertThat(back).contains("/oauth2/consent?request_id=");

		HttpResponse<String> consent = get(path(back));
		assertThat(consent.statusCode()).isEqualTo(200);
		assertThat(consent.body()).contains("Test CLI").contains("Signed in as alice");
		String requestId = consentPath.substring(consentPath.indexOf('=') + 1);
		HttpResponse<String> decision = postForm("/oauth2/consent",
				Map.of("request_id", requestId, "decision", "approve", "_csrf", csrf(consent.body())));
		assertThat(decision.statusCode()).isEqualTo(303);
		assertThat(location(decision)).startsWith("http://127.0.0.1:8765/callback?code=");
		String code = location(decision).replaceAll(".*[?&]code=([^&]+).*", "$1");

		HttpResponse<String> token = postForm("/oauth2/token", Map.of("grant_type", "authorization_code", "client_id",
				"test-cli", "code", code, "code_verifier", VERIFIER, "redirect_uri", "http://127.0.0.1:8765/callback"));
		assertThat(token.statusCode()).isEqualTo(200);
		String access = token.body().replaceAll(".*\"access_token\":\"([^\"]+)\".*", "$1");

		HttpResponse<String> mcp = this.browser.send(HttpRequest.newBuilder(uri("/mcp"))
			.header("Authorization", "Bearer " + access)
			.header("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString("{}"))
			.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(mcp.statusCode()).isEqualTo(200);
		assertThat(mcp.body()).contains("\"sub\":\"alice\"");
	}

	@Test
	void protocolErrorsKeepTheirStatusThroughTheErrorDispatch() throws Exception {
		HttpClient anonymous = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
		HttpResponse<String> wrongType = anonymous.send(HttpRequest.newBuilder(uri("/oauth2/token"))
			.header("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString("{}"))
			.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(wrongType.statusCode()).isEqualTo(415);
		HttpResponse<String> registration = anonymous.send(HttpRequest.newBuilder(uri("/oauth2/register"))
			.header("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString("{\"redirect_uris\":[\"https://c.example/cb\"]}"))
			.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(registration.statusCode()).isEqualTo(404);
		HttpResponse<String> getToken = anonymous.send(HttpRequest.newBuilder(uri("/oauth2/token")).GET().build(),
				HttpResponse.BodyHandlers.ofString());
		assertThat(getToken.statusCode()).isEqualTo(405);
		HttpResponse<String> unauthenticated = anonymous.send(HttpRequest.newBuilder(uri("/mcp"))
			.header("Content-Type", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString("{}"))
			.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(unauthenticated.statusCode()).isEqualTo(401);
		assertThat(unauthenticated.headers().firstValue("WWW-Authenticate")).hasValueSatisfying(
				v -> assertThat(v).contains("resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\""));
	}

	private HttpResponse<String> get(String path) throws Exception {
		return this.browser.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
	}

	private HttpResponse<String> postForm(String path, Map<String, String> form) throws Exception {
		String body = form.entrySet().stream().map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
			.collect(Collectors.joining("&"));
		return this.browser.send(HttpRequest.newBuilder(uri(path))
			.header("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString(body))
			.build(), HttpResponse.BodyHandlers.ofString());
	}

	private URI uri(String path) {
		return URI.create("http://localhost:" + this.port + path);
	}

	private static String location(HttpResponse<?> response) {
		return response.headers().firstValue("Location").orElseThrow();
	}

	private static String path(String location) {
		URI u = URI.create(location);
		return u.getRawPath() + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
	}

	private static String csrf(String html) {
		Matcher m = CSRF.matcher(html);
		assertThat(m.find()).as("csrf field in page").isTrue();
		return m.group(1) != null ? m.group(1) : m.group(2);
	}

	private static String enc(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

}
