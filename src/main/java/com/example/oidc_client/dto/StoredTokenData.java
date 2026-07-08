package com.example.oidc_client.dto;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public record StoredTokenData(
        String principalName,
        String clientRegistrationId,
        String accessTokenValue,
        String refreshTokenValue,
        String idTokenValue,
        String tokenType,
        Instant accessTokenIssuedAt,
        Instant accessTokenExpiresAt,
        Instant refreshTokenIssuedAt,
        Instant refreshTokenExpiresAt,
        Set<String> scopes,
        Instant savedAt
) {

    public StoredTokenData {
        scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
        savedAt = savedAt == null ? Instant.now() : savedAt;
    }

    public boolean hasPrincipalName() {
        return principalName != null && !principalName.isBlank();
    }

    public boolean hasClientRegistrationId() {
        return clientRegistrationId != null && !clientRegistrationId.isBlank();
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

    public TokenSet toTokenSet() {
        return new TokenSet(
                accessTokenValue,
                refreshTokenValue,
                idTokenValue,
                tokenType,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt,
                scopes
        );
    }

    public static StoredTokenData fromTokenSet(
            String principalName,
            String clientRegistrationId,
            TokenSet tokenSet
    ) {
        if (tokenSet == null) {
            return new StoredTokenData(
                    principalName,
                    clientRegistrationId,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    Collections.emptySet(),
                    Instant.now()
            );
        }

        return new StoredTokenData(
                principalName,
                clientRegistrationId,
                tokenSet.accessTokenValue(),
                tokenSet.refreshTokenValue(),
                tokenSet.idTokenValue(),
                tokenSet.tokenType(),
                tokenSet.accessTokenIssuedAt(),
                tokenSet.accessTokenExpiresAt(),
                tokenSet.refreshTokenIssuedAt(),
                tokenSet.refreshTokenExpiresAt(),
                tokenSet.scopes(),
                Instant.now()
        );
    }
}