// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.web;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.WebUtils;

import io.github.peppe_git.mcpauthserver.core.AuthorizationFlow;
import io.github.peppe_git.mcpauthserver.core.AuthorizationFlow.Result;
import io.github.peppe_git.mcpauthserver.core.McpEndpoints;
import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.spi.ConsentPage;
import io.github.peppe_git.mcpauthserver.spi.ConsentPageRenderer;
import io.github.peppe_git.mcpauthserver.store.PendingAuthorization;

/**
 * Authorization endpoint and consent page.
 *
 * <p>A pending request is bound to the browser session that opened it: the consent page and the
 * decision only accept request identifiers stored in that session. Sending someone the consent link of
 * one's own request therefore does not work; the consent form is also protected by CSRF.
 */
@Controller
public class AuthorizationController {

	static final String PENDING_REQUESTS = AuthorizationController.class.getName() + ".PENDING_REQUESTS";

	private static final int MAX_PENDING_PER_SESSION = 10;

	private final AuthorizationFlow flow;

	private final ConsentPageRenderer renderer;

	private final McpServerSettings settings;

	public AuthorizationController(AuthorizationFlow flow, ConsentPageRenderer renderer, McpServerSettings settings) {
		this.flow = flow;
		this.renderer = renderer;
		this.settings = settings;
	}

	@GetMapping(McpEndpoints.AUTHORIZE)
	public void authorize(@RequestParam MultiValueMap<String, String> params, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		Result result = this.flow.authorize(params);
		if (result instanceof Result.AskConsent ask) {
			bind(request.getSession(true), ask.requestId());
			redirect(response, 302, request.getContextPath() + McpEndpoints.CONSENT + "?request_id="
					+ URLEncoder.encode(ask.requestId(), StandardCharsets.UTF_8));
			return;
		}
		handle(result, request, response, 302);
	}

	@GetMapping(McpEndpoints.CONSENT)
	public void consent(@RequestParam(name = "request_id", required = false) String requestId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (!isBound(request, requestId)) {
			notBound(request, response);
			return;
		}
		Result result = this.flow.prepareConsent(requestId, authentication());
		if (result instanceof Result.RenderConsent render) {
			this.renderer.renderConsent(page(render, request), request, response);
			return;
		}
		if (result instanceof Result.RedirectToClient) {
			unbind(request, requestId);
		}
		handle(result, request, response, 302);
	}

	@PostMapping(McpEndpoints.CONSENT)
	public void decide(@RequestParam(name = "request_id", required = false) String requestId,
			@RequestParam(name = "decision", required = false) String decision, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		if (!isBound(request, requestId)) {
			notBound(request, response);
			return;
		}
		unbind(request, requestId);
		// See Other: the browser follows with a GET and never re-posts the form to the client.
		handle(this.flow.decide(requestId, authentication(), "approve".equals(decision)), request, response, 303);
	}

	private ConsentPage page(Result.RenderConsent render, HttpServletRequest request) {
		PendingAuthorization p = render.request();
		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return new ConsentPage(p.requestId(), p.clientId(), p.clientName(), p.verification(), p.verifiedDomain(),
				p.redirectUri(), RedirectUris.host(p.redirectUri()), RedirectUris.isLoopback(p.redirectUri()),
				render.scopes()
					.stream()
					.map(s -> new ConsentPage.ScopeView(s, this.settings.scopes().description(s)))
					.toList(),
				render.principal(), request.getContextPath() + McpEndpoints.CONSENT,
				(csrf == null) ? "_csrf" : csrf.getParameterName(), (csrf == null) ? "" : csrf.getToken());
	}

	private void handle(Result result, HttpServletRequest request, HttpServletResponse response, int redirectStatus)
			throws IOException {
		if (result instanceof Result.RedirectToClient r) {
			redirect(response, redirectStatus, r.location());
		}
		else if (result instanceof Result.ShowError e) {
			this.renderer.renderError(e.status(), e.error(), e.description(), request, response);
		}
		else {
			throw new IllegalStateException("Unexpected result " + result);
		}
	}

	private void notBound(HttpServletRequest request, HttpServletResponse response) throws IOException {
		this.renderer.renderError(400, "invalid_request",
				"This authorization request was not started in this browser session. Start again from the application.",
				request, response);
	}

	private static Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	private static void redirect(HttpServletResponse response, int status, String location) {
		response.setStatus(status);
		response.setHeader("Location", location);
		response.setHeader("Cache-Control", "no-store");
	}

	@SuppressWarnings("unchecked")
	private static void bind(HttpSession session, String requestId) {
		synchronized (WebUtils.getSessionMutex(session)) {
			Set<String> pending = (Set<String>) session.getAttribute(PENDING_REQUESTS);
			LinkedHashSet<String> next = (pending == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(pending);
			next.add(requestId);
			while (next.size() > MAX_PENDING_PER_SESSION) {
				next.remove(next.iterator().next());
			}
			session.setAttribute(PENDING_REQUESTS, next);
		}
	}

	@SuppressWarnings("unchecked")
	private static boolean isBound(HttpServletRequest request, String requestId) {
		HttpSession session = request.getSession(false);
		if (session == null || requestId == null) {
			return false;
		}
		synchronized (WebUtils.getSessionMutex(session)) {
			Set<String> pending = (Set<String>) session.getAttribute(PENDING_REQUESTS);
			return pending != null && pending.contains(requestId);
		}
	}

	@SuppressWarnings("unchecked")
	private static void unbind(HttpServletRequest request, String requestId) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return;
		}
		synchronized (WebUtils.getSessionMutex(session)) {
			Set<String> pending = (Set<String>) session.getAttribute(PENDING_REQUESTS);
			if (pending != null) {
				LinkedHashSet<String> next = new LinkedHashSet<>(pending);
				next.remove(requestId);
				session.setAttribute(PENDING_REQUESTS, next);
			}
		}
	}

}
