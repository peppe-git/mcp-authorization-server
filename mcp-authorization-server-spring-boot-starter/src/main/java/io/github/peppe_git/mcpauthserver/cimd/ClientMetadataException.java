// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

/**
 * A Client ID Metadata Document cannot be used. The message is for logs and audit events; the browser
 * only learns that the client is invalid.
 */
public final class ClientMetadataException extends Exception {

	private static final long serialVersionUID = 1L;

	public ClientMetadataException(String reason) {
		super(reason, null, false, false);
	}

}
