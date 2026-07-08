package com.example.oidc_client.dto;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public record TokenSet(
        String accessTokenValue,
        String refreshTokenValue,
        String idTokenValue,
        String tokenType,
        Instant accessTokenIssuedAt,
        Instant accessTokenExpiresAt,
        Instant refreshTokenIssuedAt,
        Instant refreshTokenExpiresAt,
        Set<String> scopes
) {

    public TokenSet {
        scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
    }

    public boolean hasAccessToken() {
        return accessTokenValue != null && !accessTokenValue.isBlank();
    }

    public boolean hasRefreshToken() {
        return refreshTokenValue != null && !refreshTokenValue.isBlank();
    }

    public boolean hasIdToken() {
        return idTokenValue != null && !idTokenValue.isBlank();
    }

    public boolean hasAccessTokenExpiration() {
        return accessTokenExpiresAt != null;
    }

    public boolean hasRefreshTokenExpiration() {
        return refreshTokenExpiresAt != null;
    }

    public boolean isAccessTokenExpired() {
        return accessTokenExpiresAt != null && Instant.now().isAfter(accessTokenExpiresAt);
    }

    public boolean isAccessTokenExpiringSoon(Duration threshold) {
        if (accessTokenExpiresAt == null || threshold == null) {
            return false;
        }

        Instant refreshMoment = Instant.now().plus(threshold);
        return refreshMoment.isAfter(accessTokenExpiresAt);
    }

    public boolean isRefreshTokenExpired() {
        return refreshTokenExpiresAt != null && Instant.now().isAfter(refreshTokenExpiresAt);
    }

    public String effectiveRefreshTokenValue(String fallbackRefreshTokenValue) {
        if (hasRefreshToken()) {
            return refreshTokenValue;
        }

        return fallbackRefreshTokenValue;
    }

    public static TokenSet empty() {
        return new TokenSet(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Collections.emptySet()
        );
    }
}