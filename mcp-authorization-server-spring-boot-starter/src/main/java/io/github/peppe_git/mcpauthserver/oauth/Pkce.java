// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Proof Key for Code Exchange (RFC 7636), {@code S256} only. The {@code plain} method is never accepted.
 */
public final class Pkce {

	/** The only supported {@code code_challenge_method}. */
	public static final String S256 = "S256";

	/** RFC 7636 §4.1: 43 to 128 unreserved characters. */
	private static final Pattern VERIFIER = Pattern.compile("^[A-Za-z0-9\\-._~]{43,128}$");

	/** An S256 challenge is a base64url SHA-256 without padding: always 43 characters. */
	private static final Pattern S256_CHALLENGE = Pattern.compile("^[A-Za-z0-9_-]{43}$");

	private Pkce() {
	}

	public static boolean isValidChallenge(String challenge) {
		return challenge != null && S256_CHALLENGE.matcher(challenge).matches();
	}

	/** {@code S256(verifier) == challenge}, compared in constant time. */
	public static boolean verify(String verifier, String challenge) {
		if (verifier == null || challenge == null || !VERIFIER.matcher(verifier).matches()) {
			return false;
		}
		return MessageDigest.isEqual(s256(verifier).getBytes(StandardCharsets.US_ASCII),
				challenge.getBytes(StandardCharsets.US_ASCII));
	}

	/** The S256 challenge of a verifier. */
	public static String s256(String verifier) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is not available", ex);
		}
	}

}
