package com.example.oidc_client.service;

import com.example.oidc_client.dto.TokenSet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

@Service
public class OAuth2AuthorizedClientFacade {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    public OAuth2AuthorizedClientFacade(
            OAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
        this.authorizedClientRepository = authorizedClientRepository;
    }

    public OAuth2AuthorizedClient loadAuthorizedClient(
            String registrationId,
            Authentication authentication,
            HttpServletRequest request
    ) {
        if (registrationId == null || registrationId.isBlank()) {
            return null;
        }

        if (authentication == null) {
            return null;
        }

        return authorizedClientRepository.loadAuthorizedClient(
                registrationId,
                authentication,
                request
        );
    }

    public void saveAuthorizedClient(
            OAuth2AuthorizedClient authorizedClient,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        if (authorizedClient == null || authentication == null) {
            return;
        }

        authorizedClientRepository.saveAuthorizedClient(
                authorizedClient,
                authentication,
                request,
                response
        );
    }

    public OAuth2AuthorizedClient buildAuthorizedClient(
            ClientRegistration clientRegistration,
            String principalName,
            TokenSet tokenSet
    ) {
        if (clientRegistration == null) {
            throw new IllegalArgumentException("Client registration must not be null");
        }

        if (principalName == null || principalName.isBlank()) {
            throw new IllegalArgumentException("Principal name must not be blank");
        }

        if (tokenSet == null || !tokenSet.hasAccessToken()) {
            throw new IllegalArgumentException("Access token must be present");
        }

        Instant accessTokenIssuedAt = tokenSet.accessTokenIssuedAt() == null
                ? Instant.now()
                : tokenSet.accessTokenIssuedAt();

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenSet.accessTokenValue(),
                accessTokenIssuedAt,
                tokenSet.accessTokenExpiresAt(),
                normalizeScopes(tokenSet.scopes())
        );

        OAuth2RefreshToken refreshToken = null;

        if (tokenSet.hasRefreshToken()) {
            Instant refreshTokenIssuedAt = tokenSet.refreshTokenIssuedAt() == null
                    ? Instant.now()
                    : tokenSet.refreshTokenIssuedAt();

            refreshToken = new OAuth2RefreshToken(
                    tokenSet.refreshTokenValue(),
                    refreshTokenIssuedAt
            );
        }

        return new OAuth2AuthorizedClient(
                clientRegistration,
                principalName,
                accessToken,
                refreshToken
        );
    }

    private Set<String> normalizeScopes(Set<String> scopes) {
        if (scopes == null) {
            return Collections.emptySet();
        }

        return scopes;
    }
}