// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Renders the consent page and the error page of the authorization endpoint.
 *
 * <p>The consent form must post {@code request_id}, {@code decision} ({@code approve} or {@code deny})
 * and the CSRF field to {@link ConsentPage#formAction()}. A renderer must escape every value it writes
 * and must not allow the page to be framed.
 */
public interface ConsentPageRenderer {

	void renderConsent(ConsentPage page, HttpServletRequest request, HttpServletResponse response)
			throws IOException;

	/**
	 * Renders an error that cannot be sent back to the client, because the client or its redirect URI
	 * could not be verified (sending it would be an open redirect).
	 */
	void renderError(int status, String error, String description, HttpServletRequest request,
			HttpServletResponse response) throws IOException;

}
