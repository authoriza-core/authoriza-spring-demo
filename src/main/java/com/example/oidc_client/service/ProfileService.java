package com.example.oidc_client.service;

import com.example.oidc_client.dto.ProfileViewData;
import com.example.oidc_client.dto.StoredTokenData;
import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.util.JwtPayloadDecoder;
import com.example.oidc_client.util.TokenMasker;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@Service
public class ProfileService {

    private static final String REGISTRATION_ID = "autoriza";

    private final OAuth2AuthorizedClientFacade authorizedClientService;
    private final AuthTokenStorageService tokenStorageService;
    private final TokenMasker tokenMasker;
    private final JwtPayloadDecoder jwtPayloadDecoder;

    public ProfileService(
            OAuth2AuthorizedClientFacade authorizedClientService,
            AuthTokenStorageService tokenStorageService,
            TokenMasker tokenMasker,
            JwtPayloadDecoder jwtPayloadDecoder
    ) {
        this.authorizedClientService = authorizedClientService;
        this.tokenStorageService = tokenStorageService;
        this.tokenMasker = tokenMasker;
        this.jwtPayloadDecoder = jwtPayloadDecoder;
    }

    public ProfileViewData buildProfileViewData(
            Authentication authentication,
            HttpServletRequest request
    ) {
        ProfileViewData profileViewData = new ProfileViewData();

        profileViewData.getUser().setClientRegistrationId(REGISTRATION_ID);
        profileViewData.getValidation().setLastUpdatedAt(Instant.now());

        if (authentication == null) {
            profileViewData.updateValidation();
            return profileViewData;
        }

        profileViewData.getUser().setPrincipalName(authentication.getName());

        fillUserInfo(profileViewData, authentication);

        if (request != null && hasText(profileViewData.getRawTokens().getIdToken())) {
            request.getSession(true).setAttribute(
                    "latestIdToken",
                    profileViewData.getRawTokens().getIdToken()
            );
        }

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                        REGISTRATION_ID,
                        authentication,
                        request
                );

        Optional<StoredTokenData> storedTokenData =
                tokenStorageService.findByRegistrationId(REGISTRATION_ID);

        if (authorizedClient != null) {
            fillFromAuthorizedClient(profileViewData, authorizedClient, request);
        } else {
            storedTokenData.ifPresent(tokenData ->
                    fillFromStoredTokenData(profileViewData, tokenData)
            );
        }

        storedTokenData.ifPresent(tokenData ->
                profileViewData.getValidation().setLastUpdatedAt(tokenData.savedAt())
        );

        fillJwtPayloads(profileViewData);
        profileViewData.updateValidation();

        return profileViewData;
    }

    private void fillUserInfo(
            ProfileViewData profileViewData,
            Authentication authentication
    ) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            profileViewData.getUser().setSubject(oidcUser.getSubject());
            profileViewData.getUser().setEmail(oidcUser.getEmail());
            profileViewData.getUser().setDisplayName(resolveDisplayName(oidcUser));

            if (oidcUser.getIdToken() != null) {
                String idTokenValue = oidcUser.getIdToken().getTokenValue();

                profileViewData.getRawTokens().setIdToken(idTokenValue);
                profileViewData.getRawTokens().setMaskedIdToken(
                        tokenMasker.mask(idTokenValue)
                );

                profileViewData.getParsedTokens().setIdTokenPayload(
                        jwtPayloadDecoder.decodePayload(idTokenValue)
                );
            }

            return;
        }

        profileViewData.getUser().setDisplayName(authentication.getName());
    }

    private String resolveDisplayName(OidcUser oidcUser) {
        String fullName = oidcUser.getFullName();

        if (hasText(fullName)) {
            return fullName;
        }

        String preferredUsername = oidcUser.getPreferredUsername();

        if (hasText(preferredUsername)) {
            return preferredUsername;
        }

        String email = oidcUser.getEmail();

        if (hasText(email)) {
            return email;
        }

        return oidcUser.getSubject();
    }

    private void fillFromAuthorizedClient(
            ProfileViewData profileViewData,
            OAuth2AuthorizedClient authorizedClient,
            HttpServletRequest request
    ) {
        if (authorizedClient.getAccessToken() != null) {
            String accessTokenValue =
                    authorizedClient.getAccessToken().getTokenValue();

            profileViewData.getRawTokens().setAccessToken(accessTokenValue);
            profileViewData.getRawTokens().setMaskedAccessToken(
                    tokenMasker.mask(accessTokenValue)
            );

            if (authorizedClient.getAccessToken().getTokenType() != null) {
                profileViewData.getRawTokens().setTokenType(
                        authorizedClient.getAccessToken().getTokenType().getValue()
                );
            }

            profileViewData.getRawTokens().setAccessTokenIssuedAt(
                    authorizedClient.getAccessToken().getIssuedAt()
            );
            profileViewData.getRawTokens().setAccessTokenExpiresAt(
                    authorizedClient.getAccessToken().getExpiresAt()
            );

            if (authorizedClient.getAccessToken().getExpiresAt() != null) {
                long expiresIn = Duration.between(
                        Instant.now(),
                        authorizedClient.getAccessToken().getExpiresAt()
                ).toSeconds();

                profileViewData.getRawTokens().setAccessTokenExpiresIn(
                        Math.max(expiresIn, 0)
                );
            }

            profileViewData.getRawTokens().setScopes(
                    authorizedClient.getAccessToken().getScopes()
            );
        }

        if (authorizedClient.getRefreshToken() != null) {
            String refreshTokenValue =
                    authorizedClient.getRefreshToken().getTokenValue();

            profileViewData.getRawTokens().setRefreshToken(refreshTokenValue);
            profileViewData.getRawTokens().setMaskedRefreshToken(
                    tokenMasker.mask(refreshTokenValue)
            );
            profileViewData.getRawTokens().setRefreshTokenIssuedAt(
                    authorizedClient.getRefreshToken().getIssuedAt()
            );
        }

        String idTokenValue = resolveLatestIdToken(request);

        if (!hasText(profileViewData.getRawTokens().getIdToken())
                && hasText(idTokenValue)) {
            profileViewData.getRawTokens().setIdToken(idTokenValue);
            profileViewData.getRawTokens().setMaskedIdToken(
                    tokenMasker.mask(idTokenValue)
            );
        }
    }

    private void fillFromStoredTokenData(
            ProfileViewData profileViewData,
            StoredTokenData tokenData
    ) {
        profileViewData.getUser().setPrincipalName(tokenData.principalName());
        profileViewData.getUser().setClientRegistrationId(
                tokenData.clientRegistrationId()
        );

        profileViewData.getRawTokens().setAccessToken(
                tokenData.accessTokenValue()
        );
        profileViewData.getRawTokens().setMaskedAccessToken(
                tokenMasker.mask(tokenData.accessTokenValue())
        );

        profileViewData.getRawTokens().setRefreshToken(
                tokenData.refreshTokenValue()
        );
        profileViewData.getRawTokens().setMaskedRefreshToken(
                tokenMasker.mask(tokenData.refreshTokenValue())
        );

        profileViewData.getRawTokens().setIdToken(tokenData.idTokenValue());
        profileViewData.getRawTokens().setMaskedIdToken(
                tokenMasker.mask(tokenData.idTokenValue())
        );

        profileViewData.getRawTokens().setTokenType(tokenData.tokenType());
        profileViewData.getRawTokens().setAccessTokenIssuedAt(
                tokenData.accessTokenIssuedAt()
        );
        profileViewData.getRawTokens().setAccessTokenExpiresAt(
                tokenData.accessTokenExpiresAt()
        );

        if (tokenData.accessTokenExpiresAt() != null) {
            long expiresIn = Duration.between(
                    Instant.now(),
                    tokenData.accessTokenExpiresAt()
            ).toSeconds();

            profileViewData.getRawTokens().setAccessTokenExpiresIn(
                    Math.max(expiresIn, 0)
            );
        }

        profileViewData.getRawTokens().setRefreshTokenIssuedAt(
                tokenData.refreshTokenIssuedAt()
        );
        profileViewData.getRawTokens().setRefreshTokenExpiresAt(
                tokenData.refreshTokenExpiresAt()
        );
        profileViewData.getRawTokens().setScopes(tokenData.scopes());

        profileViewData.getValidation().setLastUpdatedAt(tokenData.savedAt());
    }

    private String resolveLatestIdToken(HttpServletRequest request) {
        if (request == null || request.getSession(false) == null) {
            return null;
        }

        Object latestIdToken = request.getSession(false)
                .getAttribute("latestIdToken");

        if (latestIdToken == null) {
            return null;
        }

        return String.valueOf(latestIdToken);
    }

    private void fillJwtPayloads(ProfileViewData profileViewData) {
        String accessToken = profileViewData.getRawTokens().getAccessToken();
        String idToken = profileViewData.getRawTokens().getIdToken();

        Map<String, Object> accessTokenPayload =
                jwtPayloadDecoder.decodePayload(accessToken);
        Map<String, Object> idTokenPayload =
                jwtPayloadDecoder.decodePayload(idToken);

        profileViewData.getParsedTokens().setAccessTokenPayload(
                accessTokenPayload
        );
        profileViewData.getParsedTokens().setIdTokenPayload(idTokenPayload);

        profileViewData.getParsedTokens().setAccessTokenJti(
                getStringClaim(accessTokenPayload, "jti")
        );
        profileViewData.getParsedTokens().setIdTokenJti(
                getStringClaim(idTokenPayload, "jti")
        );

        if (profileViewData.getUser().getSubject() == null) {
            profileViewData.getUser().setSubject(
                    getStringClaim(idTokenPayload, "sub")
            );
        }

        if (profileViewData.getUser().getEmail() == null) {
            profileViewData.getUser().setEmail(
                    getStringClaim(idTokenPayload, "email")
            );
        }

        if (profileViewData.getUser().getDisplayName() == null) {
            String name = getStringClaim(idTokenPayload, "name");

            if (name == null) {
                name = getStringClaim(
                        idTokenPayload,
                        "preferred_username"
                );
            }

            profileViewData.getUser().setDisplayName(name);
        }
    }

    private String getStringClaim(
            Map<String, Object> payload,
            String claimName
    ) {
        if (payload == null || payload.isEmpty()) {
            return null;
        }

        Object value = payload.get(claimName);

        if (value == null) {
            return null;
        }

        return String.valueOf(value);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
