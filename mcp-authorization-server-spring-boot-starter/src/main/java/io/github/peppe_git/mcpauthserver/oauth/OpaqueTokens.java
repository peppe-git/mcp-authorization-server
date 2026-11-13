// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Generation and hashing of the opaque values handed out by the server.
 *
 * <p>Every secret is 256 random bits in base64url. Access and refresh tokens carry a fixed prefix so
 * that secret scanners can recognise them; the prefix is not a secret and carries no data. Only the
 * SHA-256 hash of a token or code is ever stored (ADR-0004).
 */
public final class OpaqueTokens {

	/** Prefix of access tokens. */
	public static final String ACCESS_TOKEN_PREFIX = "mcp_at_";

	/** Prefix of refresh tokens. */
	public static final String REFRESH_TOKEN_PREFIX = "mcp_rt_";

	/** Prefix of client identifiers issued by dynamic registration. */
	public static final String DYNAMIC_CLIENT_PREFIX = "mcp_client_";

	private static final SecureRandom RANDOM = new SecureRandom();

	private OpaqueTokens() {
	}

	/** 256 random bits, base64url without padding (43 characters). */
	public static String random() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/** 128 random bits, base64url without padding: identifiers that are not secrets. */
	public static String newId() {
		byte[] bytes = new byte[16];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	public static String newAccessToken() {
		return ACCESS_TOKEN_PREFIX + random();
	}

	public static String newRefreshToken() {
		return REFRESH_TOKEN_PREFIX + random();
	}

	public static String newDynamicClientId() {
		return DYNAMIC_CLIENT_PREFIX + newId();
	}

	/** Lower-case hex SHA-256 of the UTF-8 bytes of {@code value}. */
	public static String hash(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is not available", ex);
		}
	}

}
