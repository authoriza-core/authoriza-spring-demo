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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.oidc_client.storage.AuthTokenStorageService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AccessTokenAutoRefreshFilter extends OncePerRequestFilter {

    private static final String REGISTRATION_ID = "autoriza";
    private static final Duration REFRESH_BEFORE_EXPIRATION = Duration.ofMinutes(5);

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
                            request,
                            response
                    );
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        filterChain.doFilter(request, response);
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
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

        Map<String, Object> tokenResponse = requestNewTokens(
                clientRegistration,
                authorizedClient.getRefreshToken().getTokenValue()
        );

        String newAccessTokenValue = tokenResponse.get("access_token").toString();

        String newRefreshTokenValue = authorizedClient.getRefreshToken().getTokenValue();
        if (tokenResponse.get("refresh_token") != null) {
            newRefreshTokenValue = tokenResponse.get("refresh_token").toString();
        }

        String newIdTokenValue = "";
        if (tokenResponse.get("id_token") != null) {
            newIdTokenValue = tokenResponse.get("id_token").toString();
        } else if (request.getSession().getAttribute("latestIdToken") != null) {
            newIdTokenValue = request.getSession().getAttribute("latestIdToken").toString();
        }

        long expiresIn = getLongValue(tokenResponse, "expires_in", 3600);

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(expiresIn);

        Set<String> scopes = parseScopes(tokenResponse.get("scope"));

        if (scopes.isEmpty()) {
            scopes = authorizedClient.getAccessToken().getScopes();
        }

        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                newAccessTokenValue,
                issuedAt,
                expiresAt,
                scopes
        );

        OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                newRefreshTokenValue,
                issuedAt
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
                newAccessToken.getIssuedAt(),
                newAccessToken.getExpiresAt(),
                newRefreshToken.getIssuedAt(),
                null,
                null,
                newAccessToken.getScopes()
        );

        System.out.println("Access Token автоматически обновлён за 5 минут до истечения");
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