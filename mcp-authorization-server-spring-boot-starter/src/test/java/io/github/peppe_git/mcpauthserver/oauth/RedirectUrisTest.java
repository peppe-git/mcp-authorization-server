// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RedirectUrisTest {

	@Test
	void exactMatchExceptLoopbackPort() {
		List<String> registered = List.of("https://app.example/callback", "http://localhost/callback",
				"http://127.0.0.1/cb", "http://[::1]/cb");
		assertThat(RedirectUris.matchesAny("https://app.example/callback", registered)).isTrue();
		assertThat(RedirectUris.matchesAny("http://localhost:53682/callback", registered)).isTrue();
		assertThat(RedirectUris.matchesAny("http://127.0.0.1:1234/cb", registered)).isTrue();
		assertThat(RedirectUris.matchesAny("http://[::1]:9999/cb", registered)).isTrue();

		// "Any port" never becomes "any path", "any host", "any query" or "any scheme".
		assertThat(RedirectUris.matchesAny("http://localhost:53682/other", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("http://localhost:53682/callback?x=1", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("http://127.0.0.1:53682/callback", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("https://localhost:53682/callback", registered)).isFalse();
		// Non-loopback: exact, including port, path, trailing slash and case.
		assertThat(RedirectUris.matchesAny("https://app.example:8443/callback", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("https://app.example/callback/", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("https://APP.example/callback", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("https://app.example.evil/callback", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("http://localhost:53682/callback#frag", registered)).isFalse();
		assertThat(RedirectUris.matchesAny("http://user@localhost:53682/callback", registered)).isFalse();
		assertThat(RedirectUris.matchesAny(null, registered)).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "https://app.example/cb", "http://localhost/cb", "http://127.0.0.1:8080/cb",
			"http://[::1]/cb" })
	void wellFormed(String uri) {
		assertThat(RedirectUris.isWellFormed(uri)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://app.example/cb", "https://app.example/cb#x", "https://u:p@app.example/cb",
			"com.example.app:/cb", "javascript:alert(1)", "/relative", "https:///nohost", "http://10.0.0.1/cb",
			"http://127.0.0.2/cb", "ftp://app.example/cb" })
	void notWellFormed(String uri) {
		assertThat(RedirectUris.isWellFormed(uri)).isFalse();
	}

	@Test
	void hostForTheConsentPage() {
		assertThat(RedirectUris.host("https://app.example/cb")).isEqualTo("app.example");
		assertThat(RedirectUris.isLoopback("http://localhost:1/cb")).isTrue();
		assertThat(RedirectUris.isLoopback("https://localhost/cb")).isFalse();
	}

}
