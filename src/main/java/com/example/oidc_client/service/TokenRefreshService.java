package com.example.oidc_client.service;

import com.example.oidc_client.dto.StoredTokenData;
import com.example.oidc_client.dto.TokenEndpointResponse;
import com.example.oidc_client.dto.TokenRefreshResult;
import com.example.oidc_client.dto.TokenSet;
import com.example.oidc_client.storage.AuthTokenStorageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientResponseException;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

@Service
public class TokenRefreshService {

    private static final String REGISTRATION_ID = "autoriza";

    private final TokenEndpointClient tokenEndpointClient;
    private final OAuth2AuthorizedClientFacade authorizedClientService;
    private final AuthTokenStorageService tokenStorageService;
    private final TokenCleanupService tokenCleanupService;

    public TokenRefreshService(
            TokenEndpointClient tokenEndpointClient,
            OAuth2AuthorizedClientFacade authorizedClientService,
            AuthTokenStorageService tokenStorageService,
            TokenCleanupService tokenCleanupService
    ) {
        this.tokenEndpointClient = tokenEndpointClient;
        this.authorizedClientService = authorizedClientService;
        this.tokenStorageService = tokenStorageService;
        this.tokenCleanupService = tokenCleanupService;
    }

    public TokenRefreshResult refresh(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            if (authentication == null) {
                return TokenRefreshResult.failure("Пользователь не авторизован");
            }

            OAuth2AuthorizedClient authorizedClient =
                    authorizedClientService.loadAuthorizedClient(
                            REGISTRATION_ID,
                            authentication,
                            request
                    );

            if (authorizedClient == null) {
                return TokenRefreshResult.failure(
                        "OAuth2AuthorizedClient не найден в сессии"
                );
            }

            OAuth2RefreshToken currentRefreshToken =
                    authorizedClient.getRefreshToken();

            if (currentRefreshToken == null) {
                return TokenRefreshResult.failure(
                        "Refresh Token отсутствует. Обновить токены невозможно"
                );
            }

            Optional<StoredTokenData> storedTokenData =
                    tokenStorageService.findByRegistrationId(REGISTRATION_ID);

            if (isStoredRefreshTokenExpired(storedTokenData)) {
                tokenCleanupService.clearDefaultAuthorization(request);

                return TokenRefreshResult.failure(
                        "Refresh Token истёк. Нужно пройти авторизацию заново",
                        "refresh_token_expired"
                );
            }

            TokenSet refreshedTokenSet = requestAndBuildTokenSet(
                    authorizedClient,
                    currentRefreshToken,
                    storedTokenData,
                    request
            );

            OAuth2AuthorizedClient updatedClient =
                    authorizedClientService.buildAuthorizedClient(
                            authorizedClient.getClientRegistration(),
                            authorizedClient.getPrincipalName(),
                            refreshedTokenSet
                    );

            authorizedClientService.saveAuthorizedClient(
                    updatedClient,
                    authentication,
                    request,
                    response
            );

            request.getSession(true).setAttribute(
                    "latestIdToken",
                    refreshedTokenSet.idTokenValue()
            );

            tokenStorageService.saveTokenSet(
                    authorizedClient.getPrincipalName(),
                    REGISTRATION_ID,
                    refreshedTokenSet
            );

            return TokenRefreshResult.success(
                    refreshedTokenSet,
                    "Токены успешно обновлены и сохранены"
            );
        } catch (RestClientResponseException exception) {
            return TokenRefreshResult.failure(
                    "Ошибка при запросе к Token Endpoint: "
                            + exception.getStatusCode(),
                    "token_endpoint_error"
            );
        } catch (Exception exception) {
            return TokenRefreshResult.failure(
                    "Внутренняя ошибка при обновлении токенов: "
                            + exception.getMessage(),
                    "internal_error"
            );
        }
    }

    public TokenSet refreshStoredTokenSet(
            OAuth2AuthorizedClient authorizedClient,
            StoredTokenData storedTokenData,
            HttpServletRequest request
    ) {
        if (authorizedClient == null) {
            throw new IllegalArgumentException("Authorized client must not be null");
        }

        if (storedTokenData == null || !storedTokenData.hasRefreshToken()) {
            throw new IllegalArgumentException("Stored refresh token must be present");
        }

        OAuth2RefreshToken currentRefreshToken = new OAuth2RefreshToken(
                storedTokenData.refreshTokenValue(),
                storedTokenData.refreshTokenIssuedAt()
        );

        return requestAndBuildTokenSet(
                authorizedClient,
                currentRefreshToken,
                Optional.of(storedTokenData),
                request
        );
    }

    public boolean shouldRefreshAccessToken(
            OAuth2AuthorizedClient authorizedClient,
            java.time.Duration threshold
    ) {
        if (authorizedClient == null) {
            return false;
        }

        if (authorizedClient.getAccessToken() == null) {
            return false;
        }

        if (authorizedClient.getRefreshToken() == null) {
            return false;
        }

        Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();

        if (expiresAt == null || threshold == null) {
            return false;
        }

        Instant refreshMoment = expiresAt.minus(threshold);

        return Instant.now().isAfter(refreshMoment);
    }

    private TokenSet requestAndBuildTokenSet(
            OAuth2AuthorizedClient authorizedClient,
            OAuth2RefreshToken currentRefreshToken,
            Optional<StoredTokenData> storedTokenData,
            HttpServletRequest request
    ) {
        TokenEndpointResponse tokenEndpointResponse =
                tokenEndpointClient.refreshToken(
                        authorizedClient.getClientRegistration(),
                        currentRefreshToken.getTokenValue()
                );

        if (!tokenEndpointResponse.hasAccessToken()) {
            throw new IllegalStateException(
                    "Token Endpoint did not return access_token"
            );
        }

        String newRefreshTokenValue = tokenEndpointResponse.hasRefreshToken()
                ? tokenEndpointResponse.refreshToken()
                : currentRefreshToken.getTokenValue();

        boolean refreshTokenRotated =
                tokenEndpointResponse.hasRefreshToken()
                        && !tokenEndpointResponse.refreshToken()
                        .equals(currentRefreshToken.getTokenValue());

        String idTokenValue = resolveIdTokenValue(
                tokenEndpointResponse,
                storedTokenData,
                request
        );

        Set<String> scopes = resolveScopes(
                tokenEndpointResponse,
                authorizedClient,
                storedTokenData
        );

        Instant accessTokenIssuedAt = tokenEndpointResponse.accessTokenIssuedAt();
        Instant accessTokenExpiresAt = tokenEndpointResponse.accessTokenExpiresAt();

        Instant refreshTokenIssuedAt = resolveRefreshTokenIssuedAt(
                currentRefreshToken,
                refreshTokenRotated,
                accessTokenIssuedAt,
                storedTokenData
        );

        Instant refreshTokenExpiresAt = resolveRefreshTokenExpiresAt(
                refreshTokenRotated,
                storedTokenData
        );

        String tokenType = tokenEndpointResponse.tokenType() == null
                ? "Bearer"
                : tokenEndpointResponse.tokenType();

        return new TokenSet(
                tokenEndpointResponse.accessToken(),
                newRefreshTokenValue,
                idTokenValue,
                tokenType,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt,
                scopes
        );
    }

    private boolean isStoredRefreshTokenExpired(
            Optional<StoredTokenData> storedTokenData
    ) {
        return storedTokenData
                .map(StoredTokenData::toTokenSet)
                .map(TokenSet::isRefreshTokenExpired)
                .orElse(false);
    }

    private String resolveIdTokenValue(
            TokenEndpointResponse tokenEndpointResponse,
            Optional<StoredTokenData> storedTokenData,
            HttpServletRequest request
    ) {
        if (tokenEndpointResponse.hasIdToken()) {
            return tokenEndpointResponse.idToken();
        }

        if (request != null && request.getSession(false) != null) {
            Object latestIdToken = request.getSession(false)
                    .getAttribute("latestIdToken");

            if (latestIdToken != null) {
                return String.valueOf(latestIdToken);
            }
        }

        return storedTokenData
                .map(StoredTokenData::idTokenValue)
                .orElse(null);
    }

    private Set<String> resolveScopes(
            TokenEndpointResponse tokenEndpointResponse,
            OAuth2AuthorizedClient authorizedClient,
            Optional<StoredTokenData> storedTokenData
    ) {
        if (tokenEndpointResponse.scopes() != null
                && !tokenEndpointResponse.scopes().isEmpty()) {
            return tokenEndpointResponse.scopes();
        }

        if (authorizedClient.getAccessToken() != null
                && authorizedClient.getAccessToken().getScopes() != null
                && !authorizedClient.getAccessToken().getScopes().isEmpty()) {
            return authorizedClient.getAccessToken().getScopes();
        }

        return storedTokenData
                .map(StoredTokenData::scopes)
                .orElse(Collections.emptySet());
    }

    private Instant resolveRefreshTokenIssuedAt(
            OAuth2RefreshToken currentRefreshToken,
            boolean refreshTokenRotated,
            Instant fallbackIssuedAt,
            Optional<StoredTokenData> storedTokenData
    ) {
        if (refreshTokenRotated) {
            return fallbackIssuedAt;
        }

        if (currentRefreshToken.getIssuedAt() != null) {
            return currentRefreshToken.getIssuedAt();
        }

        return storedTokenData
                .map(StoredTokenData::refreshTokenIssuedAt)
                .orElse(fallbackIssuedAt);
    }

    private Instant resolveRefreshTokenExpiresAt(
            boolean refreshTokenRotated,
            Optional<StoredTokenData> storedTokenData
    ) {
        if (refreshTokenRotated) {
            return null;
        }

        return storedTokenData
                .map(StoredTokenData::refreshTokenExpiresAt)
                .orElse(null);
    }
}