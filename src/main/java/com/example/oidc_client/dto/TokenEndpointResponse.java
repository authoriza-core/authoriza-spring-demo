package com.example.oidc_client.dto;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public record TokenEndpointResponse(
        String accessToken,
        String refreshToken,
        String idToken,
        String tokenType,
        Integer expiresIn,
        String scope,
        Set<String> scopes,
        Instant receivedAt
) {

    public TokenEndpointResponse {
        scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
        receivedAt = receivedAt == null ? Instant.now() : receivedAt;
    }

    public boolean hasAccessToken() {
        return accessToken != null && !accessToken.isBlank();
    }

    public boolean hasRefreshToken() {
        return refreshToken != null && !refreshToken.isBlank();
    }

    public boolean hasIdToken() {
        return idToken != null && !idToken.isBlank();
    }

    public Instant accessTokenIssuedAt() {
        return receivedAt;
    }

    public Instant accessTokenExpiresAt() {
        if (expiresIn == null || expiresIn <= 0) {
            return null;
        }

        return receivedAt.plusSeconds(expiresIn);
    }

    public TokenSet toTokenSet(String fallbackRefreshTokenValue) {
        String effectiveRefreshToken = hasRefreshToken()
                ? refreshToken
                : fallbackRefreshTokenValue;

        return new TokenSet(
                accessToken,
                effectiveRefreshToken,
                idToken,
                tokenType,
                accessTokenIssuedAt(),
                accessTokenExpiresAt(),
                null,
                null,
                scopes
        );
    }
}