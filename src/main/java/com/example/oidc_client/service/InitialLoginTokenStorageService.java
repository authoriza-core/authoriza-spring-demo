package com.example.oidc_client.service;

import com.example.oidc_client.dto.TokenSet;
import com.example.oidc_client.storage.AuthTokenStorageService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

@Service
public class InitialLoginTokenStorageService {

    private static final String REGISTRATION_ID = "autoriza";

    private final OAuth2AuthorizedClientFacade authorizedClientFacade;
    private final AuthTokenStorageService tokenStorageService;

    public InitialLoginTokenStorageService(
            OAuth2AuthorizedClientFacade authorizedClientFacade,
            AuthTokenStorageService tokenStorageService
    ) {
        this.authorizedClientFacade = authorizedClientFacade;
        this.tokenStorageService = tokenStorageService;
    }

    public void saveAfterLogin(
            Authentication authentication,
            HttpServletRequest request
    ) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken)) {
            return;
        }

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientFacade.loadAuthorizedClient(
                        REGISTRATION_ID,
                        oauth2AuthenticationToken,
                        request
                );

        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return;
        }

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        String idTokenValue = resolveIdToken(authentication);

        if (idTokenValue != null && !idTokenValue.isBlank()) {
            request.getSession(true).setAttribute("latestIdToken", idTokenValue);
        }

        Set<String> scopes = accessToken.getScopes() == null
                ? Collections.emptySet()
                : accessToken.getScopes();

        TokenSet tokenSet = new TokenSet(
                accessToken.getTokenValue(),
                refreshToken == null ? null : refreshToken.getTokenValue(),
                idTokenValue,
                accessToken.getTokenType() == null
                        ? "Bearer"
                        : accessToken.getTokenType().getValue(),
                accessToken.getIssuedAt(),
                accessToken.getExpiresAt(),
                refreshToken == null ? null : refreshToken.getIssuedAt(),
                null,
                scopes
        );

        tokenStorageService.saveTokenSet(
                authentication.getName(),
                REGISTRATION_ID,
                tokenSet
        );
    }

    private String resolveIdToken(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof OidcUser oidcUser
                && oidcUser.getIdToken() != null) {
            return oidcUser.getIdToken().getTokenValue();
        }

        return null;
    }
}