package com.example.oidc_client.storage;

import java.time.Instant;
import java.util.Set;
import java.util.StringJoiner;

import org.springframework.stereotype.Service;

@Service
public class AuthTokenStorageService {

    private final StoredAuthDataRepository repository;

    public AuthTokenStorageService(StoredAuthDataRepository repository) {
        this.repository = repository;
    }

    public void saveTokens(
            String registrationId,
            String principalName,
            String accessToken,
            String refreshToken,
            String idToken,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt,
            Instant refreshTokenIssuedAt,
            Instant refreshTokenExpiresAt,
            Instant idTokenIssuedAt,
            Instant idTokenExpiresAt,
            Set<String> scopes
    ) {
        StoredAuthData data = new StoredAuthData();

        data.setRegistrationId(registrationId);
        data.setPrincipalName(principalName);
        data.setAccessToken(accessToken);
        data.setRefreshToken(refreshToken);
        data.setIdToken(idToken);
        data.setAccessTokenIssuedAt(accessTokenIssuedAt);
        data.setAccessTokenExpiresAt(accessTokenExpiresAt);
        data.setRefreshTokenIssuedAt(refreshTokenIssuedAt);
        data.setIdTokenIssuedAt(idTokenIssuedAt);
        data.setIdTokenExpiresAt(idTokenExpiresAt);
        data.setScopes(joinScopes(scopes));
        data.setLastUpdatedAt(Instant.now());
        data.setRefreshTokenIssuedAt(refreshTokenIssuedAt);
        data.setRefreshTokenExpiresAt(refreshTokenExpiresAt);

        repository.save(data);
    }

    public StoredAuthData findByRegistrationId(String registrationId) {
        return repository.findById(registrationId).orElse(null);
    }

    public void deleteByRegistrationId(String registrationId) {
        repository.deleteById(registrationId);
    }

    private String joinScopes(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }

        StringJoiner joiner = new StringJoiner(" ");

        for (String scope : scopes) {
            joiner.add(scope);
        }

        return joiner.toString();
    }
}