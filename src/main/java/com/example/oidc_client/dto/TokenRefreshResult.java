package com.example.oidc_client.dto;

import java.time.Instant;

public record TokenRefreshResult(
        boolean success,
        String message,
        String errorCode,
        TokenSet tokenSet,
        Instant refreshedAt
) {

    public TokenRefreshResult {
        refreshedAt = refreshedAt == null ? Instant.now() : refreshedAt;
    }

    public boolean hasTokens() {
        return tokenSet != null && tokenSet.hasAccessToken();
    }

    public boolean hasError() {
        return !success;
    }

    public static TokenRefreshResult success(TokenSet tokenSet) {
        return new TokenRefreshResult(
                true,
                "Токены успешно обновлены",
                null,
                tokenSet,
                Instant.now()
        );
    }

    public static TokenRefreshResult success(TokenSet tokenSet, String message) {
        return new TokenRefreshResult(
                true,
                message,
                null,
                tokenSet,
                Instant.now()
        );
    }

    public static TokenRefreshResult failure(String message) {
        return new TokenRefreshResult(
                false,
                message,
                null,
                null,
                Instant.now()
        );
    }

    public static TokenRefreshResult failure(String message, String errorCode) {
        return new TokenRefreshResult(
                false,
                message,
                errorCode,
                null,
                Instant.now()
        );
    }
}