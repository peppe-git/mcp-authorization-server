// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

/**
 * A client name is written by whoever registers the client and ends up in front of the user on the
 * consent page. Control and format characters are removed (including bidirectional overrides: a name
 * that reads backwards is a classic phishing trick) and the result is cut to a label length.
 */
public final class ClientNames {

	/** Maximum length of a displayed client name. */
	public static final int MAX_LENGTH = 80;

	private ClientNames() {
	}

	public static String sanitize(String raw, String fallback) {
		String s = (raw == null) ? "" : raw.replaceAll("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]", "").strip();
		if (s.isEmpty()) {
			s = (fallback == null) ? "" : fallback;
		}
		if (s.length() > MAX_LENGTH) {
			int end = MAX_LENGTH;
			if (Character.isHighSurrogate(s.charAt(end - 1))) {
				end--;
			}
			s = s.substring(0, end);
		}
		return s;
	}

}
