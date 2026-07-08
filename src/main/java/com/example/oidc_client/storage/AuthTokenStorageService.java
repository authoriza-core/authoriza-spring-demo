package com.example.oidc_client.storage;

import com.example.oidc_client.dto.StoredTokenData;
import com.example.oidc_client.dto.TokenSet;
import com.example.oidc_client.util.TokenScopeParser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

@Service
public class AuthTokenStorageService {

    private final StoredAuthDataRepository repository;
    private final TokenScopeParser tokenScopeParser;

    public AuthTokenStorageService(
            StoredAuthDataRepository repository,
            TokenScopeParser tokenScopeParser
    ) {
        this.repository = repository;
        this.tokenScopeParser = tokenScopeParser;
    }

    @Transactional
    public StoredTokenData save(StoredTokenData tokenData) {
        if (tokenData == null) {
            throw new IllegalArgumentException("Token data must not be null");
        }

        if (!tokenData.hasClientRegistrationId()) {
            throw new IllegalArgumentException("Client registration id must not be blank");
        }

        StoredAuthData entity = toEntity(tokenData);
        StoredAuthData savedEntity = repository.save(entity);

        return toDto(savedEntity);
    }

    @Transactional
    public StoredTokenData saveTokenSet(
            String principalName,
            String clientRegistrationId,
            TokenSet tokenSet
    ) {
        StoredTokenData tokenData = StoredTokenData.fromTokenSet(
                principalName,
                clientRegistrationId,
                tokenSet
        );

        return save(tokenData);
    }

    @Transactional(readOnly = true)
    public Optional<StoredTokenData> findByRegistrationId(String registrationId) {
        if (registrationId == null || registrationId.isBlank()) {
            return Optional.empty();
        }

        return repository.findById(registrationId)
                .map(this::toDto);
    }

    @Transactional(readOnly = true)
    public Optional<StoredTokenData> findByRegistrationIdAndPrincipalName(
            String registrationId,
            String principalName
    ) {
        if (registrationId == null || registrationId.isBlank()) {
            return Optional.empty();
        }

        if (principalName == null || principalName.isBlank()) {
            return Optional.empty();
        }

        return repository.findByRegistrationIdAndPrincipalName(registrationId, principalName)
                .map(this::toDto);
    }

    @Transactional(readOnly = true)
    public boolean existsByRegistrationId(String registrationId) {
        if (registrationId == null || registrationId.isBlank()) {
            return false;
        }

        return repository.existsById(registrationId);
    }

    @Transactional
    public void deleteByRegistrationId(String registrationId) {
        if (registrationId == null || registrationId.isBlank()) {
            return;
        }

        repository.deleteById(registrationId);
    }

    @Transactional
    public void deleteByRegistrationIdAndPrincipalName(
            String registrationId,
            String principalName
    ) {
        if (registrationId == null || registrationId.isBlank()) {
            return;
        }

        if (principalName == null || principalName.isBlank()) {
            return;
        }

        repository.deleteByRegistrationIdAndPrincipalName(registrationId, principalName);
    }

    @Transactional
    public void deleteAllTokens() {
        repository.deleteAll();
    }

    @Transactional
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
        StoredTokenData tokenData = new StoredTokenData(
                principalName,
                registrationId,
                accessToken,
                refreshToken,
                idToken,
                "Bearer",
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt,
                scopes,
                Instant.now()
        );

        save(tokenData);
    }

    private StoredAuthData toEntity(StoredTokenData tokenData) {
        StoredAuthData entity = new StoredAuthData();

        entity.setRegistrationId(tokenData.clientRegistrationId());
        entity.setPrincipalName(tokenData.principalName());

        entity.setAccessToken(tokenData.accessTokenValue());
        entity.setRefreshToken(tokenData.refreshTokenValue());
        entity.setIdToken(tokenData.idTokenValue());
        entity.setTokenType(tokenData.tokenType());

        entity.setAccessTokenIssuedAt(tokenData.accessTokenIssuedAt());
        entity.setAccessTokenExpiresAt(tokenData.accessTokenExpiresAt());

        entity.setRefreshTokenIssuedAt(tokenData.refreshTokenIssuedAt());
        entity.setRefreshTokenExpiresAt(tokenData.refreshTokenExpiresAt());

        entity.setIdTokenIssuedAt(null);
        entity.setIdTokenExpiresAt(null);

        entity.setScopes(tokenScopeParser.join(tokenData.scopes()));
        entity.setLastUpdatedAt(tokenData.savedAt() == null ? Instant.now() : tokenData.savedAt());

        return entity;
    }

    private StoredTokenData toDto(StoredAuthData entity) {
        if (entity == null) {
            return null;
        }

        Set<String> scopes = entity.getScopes() == null
                ? Collections.emptySet()
                : tokenScopeParser.parse(entity.getScopes());

        return new StoredTokenData(
                entity.getPrincipalName(),
                entity.getRegistrationId(),
                entity.getAccessToken(),
                entity.getRefreshToken(),
                entity.getIdToken(),
                entity.getTokenType(),
                entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiresAt(),
                entity.getRefreshTokenIssuedAt(),
                entity.getRefreshTokenExpiresAt(),
                scopes,
                entity.getLastUpdatedAt()
        );
    }
}