
package com.example.oidc_client.config;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.storage.StoredAuthData;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class AccessTokenAutoRefreshFilter extends OncePerRequestFilter {

    private static final String REGISTRATION_ID = "autoriza";
    private static final Duration REFRESH_BEFORE_EXPIRATION = Duration.ofMinutes(5);
    private static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofMinutes(15);

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AuthTokenStorageService tokenStorageService;
    private final RestClient restClient;

    public AccessTokenAutoRefreshFilter(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            AuthTokenStorageService tokenStorageService
    ) {
        this.authorizedClientRepository = authorizedClientRepository;
        this.tokenStorageService = tokenStorageService;
        this.restClient = RestClient.create();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                StoredAuthData storedAuthData = tokenStorageService.findByRegistrationId(REGISTRATION_ID);

                if (isRefreshTokenExpired(storedAuthData)) {
                    clearSavedAuthData(request);

                    response.sendRedirect("/oauth2/authorization/" + REGISTRATION_ID);
                    return;
                }

                OAuth2AuthorizedClient authorizedClient =
                        authorizedClientRepository.loadAuthorizedClient(
                                REGISTRATION_ID,
                                oauth2AuthenticationToken,
                                request
                        );

                if (shouldRefreshAccessToken(authorizedClient)) {
                    refreshAccessToken(
                            authorizedClient,
                            oauth2AuthenticationToken,
                            storedAuthData,
                            request,
                            response
                    );
                }
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            exception.printStackTrace();

            clearSavedAuthData(request);

            if (!response.isCommitted()) {
                response.sendRedirect("/oauth2/authorization/" + REGISTRATION_ID);
            }
        }
    }

    private boolean isRefreshTokenExpired(StoredAuthData storedAuthData) {
        if (storedAuthData == null) {
            return false;
        }

        Instant refreshTokenExpiresAt = storedAuthData.getRefreshTokenExpiresAt();

        if (refreshTokenExpiresAt == null) {
            return false;
        }

        return !refreshTokenExpiresAt.isAfter(Instant.now());
    }

    private boolean shouldRefreshAccessToken(OAuth2AuthorizedClient authorizedClient) {
        if (authorizedClient == null) {
            return false;
        }

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        if (accessToken == null || refreshToken == null) {
            return false;
        }

        Instant expiresAt = accessToken.getExpiresAt();

        if (expiresAt == null) {
            return false;
        }

        Instant refreshMoment = expiresAt.minus(REFRESH_BEFORE_EXPIRATION);

        return Instant.now().isAfter(refreshMoment);
    }

    private void refreshAccessToken(
            OAuth2AuthorizedClient authorizedClient,
            OAuth2AuthenticationToken authentication,
            StoredAuthData storedAuthData,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

        OAuth2RefreshToken oldRefreshToken = authorizedClient.getRefreshToken();

        Map<String, Object> tokenResponse = requestNewTokens(
                clientRegistration,
                oldRefreshToken.getTokenValue()
        );

        String newAccessTokenValue = tokenResponse.get("access_token").toString();

        String newRefreshTokenValue = oldRefreshToken.getTokenValue();

        boolean refreshTokenRotated = false;

        if (tokenResponse.get("refresh_token") != null) {
            newRefreshTokenValue = tokenResponse.get("refresh_token").toString();
            refreshTokenRotated = !newRefreshTokenValue.equals(oldRefreshToken.getTokenValue());
        }

        String newIdTokenValue = getCurrentIdTokenValue(tokenResponse, request, storedAuthData);

        long expiresIn = getLongValue(tokenResponse, "expires_in", 3600);

        Instant issuedAt = Instant.now();
        Instant accessTokenExpiresAt = issuedAt.plusSeconds(expiresIn);

        Set<String> scopes = parseScopes(tokenResponse.get("scope"));

        if (scopes.isEmpty()) {
            scopes = authorizedClient.getAccessToken().getScopes();
        }

        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                newAccessTokenValue,
                issuedAt,
                accessTokenExpiresAt,
                scopes
        );

        Instant refreshTokenIssuedAt = refreshTokenRotated
                ? issuedAt
                : oldRefreshToken.getIssuedAt();

        if (refreshTokenIssuedAt == null) {
            refreshTokenIssuedAt = issuedAt;
        }

        Instant refreshTokenExpiresAt = calculateRefreshTokenExpiresAt(
                storedAuthData,
                refreshTokenRotated,
                refreshTokenIssuedAt
        );

        OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                newRefreshTokenValue,
                refreshTokenIssuedAt
        );

        OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                clientRegistration,
                authentication.getName(),
                newAccessToken,
                newRefreshToken
        );

        authorizedClientRepository.saveAuthorizedClient(
                updatedClient,
                authentication,
                request,
                response
        );

        request.getSession().setAttribute("latestIdToken", newIdTokenValue);

        tokenStorageService.saveTokens(
                REGISTRATION_ID,
                authentication.getName(),
                newAccessTokenValue,
                newRefreshTokenValue,
                newIdTokenValue,
                issuedAt,
                accessTokenExpiresAt,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt,
                storedAuthData != null ? storedAuthData.getIdTokenIssuedAt() : null,
                storedAuthData != null ? storedAuthData.getIdTokenExpiresAt() : null,
                scopes
        );

        System.out.println("Access Token автоматически обновлён за 5 минут до истечения");
    }

    private String getCurrentIdTokenValue(
            Map<String, Object> tokenResponse,
            HttpServletRequest request,
            StoredAuthData storedAuthData
    ) {
        if (tokenResponse.get("id_token") != null) {
            return tokenResponse.get("id_token").toString();
        }

        Object latestIdToken = request.getSession().getAttribute("latestIdToken");

        if (latestIdToken != null) {
            return latestIdToken.toString();
        }

        if (storedAuthData != null && storedAuthData.getIdToken() != null) {
            return storedAuthData.getIdToken();
        }

        return "";
    }

    private Instant calculateRefreshTokenExpiresAt(
            StoredAuthData storedAuthData,
            boolean refreshTokenRotated,
            Instant refreshTokenIssuedAt
    ) {
        if (!refreshTokenRotated
                && storedAuthData != null
                && storedAuthData.getRefreshTokenExpiresAt() != null) {
            return storedAuthData.getRefreshTokenExpiresAt();
        }

        return refreshTokenIssuedAt.plus(REFRESH_TOKEN_LIFETIME);
    }

    private void clearSavedAuthData(HttpServletRequest request) {
        tokenStorageService.deleteByRegistrationId(REGISTRATION_ID);

        SecurityContextHolder.clearContext();

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }
    }

    private Map<String, Object> requestNewTokens(
            ClientRegistration clientRegistration,
            String refreshToken
    ) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();

        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("client_id", clientRegistration.getClientId());
        form.add("client_secret", clientRegistration.getClientSecret());

        return restClient.post()
                .uri(clientRegistration.getProviderDetails().getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {});
    }

    private long getLongValue(Map<String, Object> map, String key, long defaultValue) {
        Object value = map.get(key);

        if (value instanceof Number number) {
            return number.longValue();
        }

        if (value instanceof String stringValue) {
            return Long.parseLong(stringValue);
        }

        return defaultValue;
    }

    private Set<String> parseScopes(Object scopeValue) {
        Set<String> scopes = new HashSet<>();

        if (scopeValue == null) {
            return scopes;
        }

        String[] scopeParts = scopeValue.toString().split(" ");

        for (String scope : scopeParts) {
            if (!scope.isBlank()) {
                scopes.add(scope);
            }
        }

        return scopes;
    }
}

