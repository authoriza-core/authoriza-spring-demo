package com.example.oidc_client.config;

import com.example.oidc_client.dto.TokenRefreshResult;
import com.example.oidc_client.service.OAuth2AuthorizedClientFacade;
import com.example.oidc_client.service.TokenCleanupService;
import com.example.oidc_client.service.TokenRefreshService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class AccessTokenAutoRefreshFilter extends OncePerRequestFilter {

    private static final String REGISTRATION_ID = "autoriza";
    private static final Duration REFRESH_BEFORE_EXPIRATION = Duration.ofMinutes(5);

    private final OAuth2AuthorizedClientFacade authorizedClientService;
    private final TokenRefreshService tokenRefreshService;
    private final TokenCleanupService tokenCleanupService;

    public AccessTokenAutoRefreshFilter(
            OAuth2AuthorizedClientFacade authorizedClientService,
            TokenRefreshService tokenRefreshService,
            TokenCleanupService tokenCleanupService) {
        this.authorizedClientService = authorizedClientService;
        this.tokenRefreshService = tokenRefreshService;
        this.tokenCleanupService = tokenCleanupService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                        REGISTRATION_ID,
                        oauth2AuthenticationToken,
                        request);

                if (tokenRefreshService.shouldRefreshAccessToken(
                        authorizedClient,
                        REFRESH_BEFORE_EXPIRATION)) {
                    TokenRefreshResult refreshResult = tokenRefreshService.refresh(
                            oauth2AuthenticationToken,
                            request,
                            response);

                    if (!refreshResult.success()) {
                        handleRefreshFailure(request, response, refreshResult);
                        return;
                    }
                }
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            tokenCleanupService.clearDefaultAuthorization(request);

            if (!response.isCommitted()) {
                response.sendRedirect("/oauth2/authorization/" + REGISTRATION_ID);
            }
        }
    }

    private void handleRefreshFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            TokenRefreshResult refreshResult) throws IOException {
        if ("refresh_token_expired".equals(refreshResult.errorCode())) {
            tokenCleanupService.clearDefaultAuthorization(request);

            if (!response.isCommitted()) {
                response.sendRedirect("/oauth2/authorization/" + REGISTRATION_ID);
            }

            return;
        }

        if (!response.isCommitted()) {
            response.sendRedirect("/profile?refreshError=true");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        return path.equals("/")
                || path.equals("/error")
                || path.equals("/restore-session")
                || path.startsWith("/oauth2/")
                || path.startsWith("/login/")
                || path.startsWith("/logout")
                || path.startsWith("/h2-console")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || path.startsWith("/webjars/");
    }
}