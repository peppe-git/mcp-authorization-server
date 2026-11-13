// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PkceTest {

	@Test
	void s256OfTheRfc7636AppendixBExample() {
		String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		assertThat(Pkce.s256(verifier)).isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
		assertThat(Pkce.verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")).isTrue();
	}

	@Test
	void plainNeverMatches() {
		String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		// With the plain method the challenge would equal the verifier: S256 verification must refuse it.
		assertThat(Pkce.verify(verifier, verifier)).isFalse();
	}

	@Test
	void verifierAndChallengeShapes() {
		assertThat(Pkce.verify("short", Pkce.s256("short"))).isFalse();
		assertThat(Pkce.verify("a".repeat(129), Pkce.s256("a".repeat(129)))).isFalse();
		assertThat(Pkce.verify("a".repeat(43) + " ", Pkce.s256("a".repeat(43) + " "))).isFalse();
		assertThat(Pkce.verify(null, "x")).isFalse();
		assertThat(Pkce.isValidChallenge(Pkce.s256("a".repeat(43)))).isTrue();
		assertThat(Pkce.isValidChallenge("a".repeat(42))).isFalse();
		assertThat(Pkce.isValidChallenge("a".repeat(43) + "=")).isFalse();
	}

}
