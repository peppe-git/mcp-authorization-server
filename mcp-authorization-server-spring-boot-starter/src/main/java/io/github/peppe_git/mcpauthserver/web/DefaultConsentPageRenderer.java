// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.util.HtmlUtils;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage;
import io.github.peppe_git.mcpauthserver.spi.ConsentPageRenderer;

/**
 * A plain, self-contained consent page: no script, no external resource, every value escaped, a
 * Content Security Policy that forbids framing.
 *
 * <p>It shows what the MCP specification asks for: the client and how much its identity is verified, the
 * host of the redirect URI, a warning when the redirect goes to this computer, and the scopes.
 */
public class DefaultConsentPageRenderer implements ConsentPageRenderer {

	private static final String STYLE = "body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;"
			+ "padding:0 1rem;line-height:1.5;color:#1b1b1b;background:#fff}"
			+ "h1{font-size:1.4rem}.muted{color:#555;font-size:.9rem;word-break:break-all}"
			+ ".warn{background:#fff4e5;border:1px solid #f0b46c;padding:.6rem .8rem;border-radius:.4rem}"
			+ "ul{padding-left:1.2rem}button{font-size:1rem;padding:.5rem 1.2rem;margin-right:.6rem}"
			+ "@media (prefers-color-scheme:dark){body{color:#eee;background:#161616}.muted{color:#aaa}"
			+ ".warn{background:#3a2a12;border-color:#8a5a1c}}";

	@Override
	public void renderConsent(ConsentPage page, HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		StringBuilder html = new StringBuilder();
		html.append("<h1>Authorize ").append(e(page.clientName())).append("?</h1>");
		switch (page.verification()) {
			case DOMAIN -> html.append("<p>Published by <strong>").append(e(page.verifiedDomain()))
				.append("</strong>. The name above is chosen by the owner of that domain.</p>");
			case OPERATOR -> html.append("<p>This application is registered by the operator of this service.</p>");
			default -> html.append("<p class=\"warn\">This application registered itself: its name is "
					+ "<strong>not verified</strong>. Continue only if you started the connection yourself.</p>");
		}
		html.append("<p class=\"muted\">Client: ").append(e(page.clientId())).append("</p>");
		if (page.loopbackRedirect()) {
			html.append("<p class=\"warn\">The authorization will be handed to a program running on "
					+ "<strong>this computer</strong> (").append(e(page.redirectHost()))
				.append("). Continue only if you just started that program yourself.</p>");
		}
		else {
			html.append("<p>After your decision you will be sent to <strong>").append(e(page.redirectHost()))
				.append("</strong>.</p>");
		}
		if (page.scopes().isEmpty()) {
			html.append("<p>It asks for no specific permission.</p>");
		}
		else {
			html.append("<p>It will be able to:</p><ul>");
			for (ConsentPage.ScopeView s : page.scopes()) {
				html.append("<li>").append(e(s.description())).append(" <span class=\"muted\">(")
					.append(e(s.name())).append(")</span></li>");
			}
			html.append("</ul>");
		}
		html.append("<p class=\"muted\">Signed in as ").append(e(page.principal().displayName())).append("</p>");
		html.append("<form method=\"post\" action=\"").append(e(page.formAction())).append("\">")
			.append("<input type=\"hidden\" name=\"request_id\" value=\"").append(e(page.requestId())).append("\">")
			.append("<input type=\"hidden\" name=\"").append(e(page.csrfParameterName())).append("\" value=\"")
			.append(e(page.csrfToken())).append("\">")
			.append("<button type=\"submit\" name=\"decision\" value=\"approve\">Allow</button>")
			.append("<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form>");
		write(response, 200, "Authorize " + page.clientName(), html.toString());
	}

	@Override
	public void renderError(int status, String error, String description, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		String html = "<h1>Authorization failed</h1><p>" + e(description) + "</p><p class=\"muted\">Error: "
				+ e(error) + "</p>";
		write(response, status, "Authorization failed", html);
	}

	private static void write(HttpServletResponse response, int status, String title, String body) throws IOException {
		response.setStatus(status);
		response.setContentType("text/html;charset=UTF-8");
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Content-Security-Policy",
				"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
		response.setHeader("X-Frame-Options", "DENY");
		response.setHeader("Referrer-Policy", "no-referrer");
		PrintWriter out = response.getWriter();
		out.write("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
				+ "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + e(title)
				+ "</title><style>" + STYLE + "</style></head><body>" + body + "</body></html>");
		out.flush();
	}

	private static String e(String value) {
		return (value == null) ? "" : HtmlUtils.htmlEscape(value, "UTF-8");
	}

}
