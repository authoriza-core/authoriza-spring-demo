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
        profileViewData.setClientRegistrationId(REGISTRATION_ID);
        profileViewData.setLastUpdatedAt(Instant.now());

        if (authentication == null) {
            return profileViewData;
        }

        profileViewData.setPrincipalName(authentication.getName());

        fillUserInfo(profileViewData, authentication);
        if (request != null
                && profileViewData.getIdToken() != null
                && !profileViewData.getIdToken().isBlank()) {
            request.getSession(true).setAttribute(
                    "latestIdToken",
                    profileViewData.getIdToken()
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
                profileViewData.setLastUpdatedAt(tokenData.savedAt())
        );

        fillJwtPayloads(profileViewData);

        return profileViewData;
    }

    private void fillUserInfo(
            ProfileViewData profileViewData,
            Authentication authentication
    ) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            profileViewData.setSubject(oidcUser.getSubject());
            profileViewData.setEmail(oidcUser.getEmail());
            profileViewData.setDisplayName(resolveDisplayName(oidcUser));

            if (oidcUser.getIdToken() != null) {
                String idTokenValue = oidcUser.getIdToken().getTokenValue();

                profileViewData.setIdToken(idTokenValue);
                profileViewData.setMaskedIdToken(tokenMasker.mask(idTokenValue));

                profileViewData.setIdTokenPayload(
                        jwtPayloadDecoder.decodePayload(idTokenValue)
                );
            }

            return;
        }

        profileViewData.setDisplayName(authentication.getName());
    }

    private String resolveDisplayName(OidcUser oidcUser) {
        String fullName = oidcUser.getFullName();

        if (fullName != null && !fullName.isBlank()) {
            return fullName;
        }

        String preferredUsername = oidcUser.getPreferredUsername();

        if (preferredUsername != null && !preferredUsername.isBlank()) {
            return preferredUsername;
        }

        String email = oidcUser.getEmail();

        if (email != null && !email.isBlank()) {
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
            profileViewData.setAccessToken(
                    authorizedClient.getAccessToken().getTokenValue()
            );

            profileViewData.setMaskedAccessToken(
                    tokenMasker.mask(
                            authorizedClient.getAccessToken().getTokenValue()
                    )
            );

            profileViewData.setTokenType(
                    authorizedClient.getAccessToken().getTokenType().getValue()
            );

            profileViewData.setAccessTokenIssuedAt(
                    authorizedClient.getAccessToken().getIssuedAt()
            );

            profileViewData.setAccessTokenExpiresAt(
                    authorizedClient.getAccessToken().getExpiresAt()
            );
            if (authorizedClient.getAccessToken().getExpiresAt() != null) {
                long expiresIn = java.time.Duration.between(
                        java.time.Instant.now(),
                        authorizedClient.getAccessToken().getExpiresAt()
                ).toSeconds();

                profileViewData.setAccessTokenExpiresIn(Math.max(expiresIn, 0));
            }

            profileViewData.setScopes(
                    authorizedClient.getAccessToken().getScopes()
            );
        }

        if (authorizedClient.getRefreshToken() != null) {
            profileViewData.setRefreshToken(
                    authorizedClient.getRefreshToken().getTokenValue()
            );

            profileViewData.setMaskedRefreshToken(
                    tokenMasker.mask(
                            authorizedClient.getRefreshToken().getTokenValue()
                    )
            );

            profileViewData.setRefreshTokenIssuedAt(
                    authorizedClient.getRefreshToken().getIssuedAt()
            );
        }

        String idTokenValue = resolveLatestIdToken(request);

        if ((profileViewData.getIdToken() == null || profileViewData.getIdToken().isBlank())
                && idTokenValue != null
                && !idTokenValue.isBlank()) {
            profileViewData.setIdToken(idTokenValue);
            profileViewData.setMaskedIdToken(tokenMasker.mask(idTokenValue));
        }
    }

    private void fillFromStoredTokenData(
            ProfileViewData profileViewData,
            StoredTokenData tokenData
    ) {
        profileViewData.setPrincipalName(tokenData.principalName());
        profileViewData.setClientRegistrationId(tokenData.clientRegistrationId());

        profileViewData.setAccessToken(tokenData.accessTokenValue());
        profileViewData.setMaskedAccessToken(
                tokenMasker.mask(tokenData.accessTokenValue())
        );

        profileViewData.setRefreshToken(tokenData.refreshTokenValue());
        profileViewData.setMaskedRefreshToken(
                tokenMasker.mask(tokenData.refreshTokenValue())
        );

        profileViewData.setIdToken(tokenData.idTokenValue());
        profileViewData.setMaskedIdToken(
                tokenMasker.mask(tokenData.idTokenValue())
        );

        profileViewData.setTokenType(tokenData.tokenType());

        profileViewData.setAccessTokenIssuedAt(tokenData.accessTokenIssuedAt());
        profileViewData.setAccessTokenExpiresAt(tokenData.accessTokenExpiresAt());
        if (tokenData.accessTokenExpiresAt() != null) {
            long expiresIn = java.time.Duration.between(
                    java.time.Instant.now(),
                    tokenData.accessTokenExpiresAt()
            ).toSeconds();

            profileViewData.setAccessTokenExpiresIn(Math.max(expiresIn, 0));
        }
        profileViewData.setRefreshTokenIssuedAt(tokenData.refreshTokenIssuedAt());
        profileViewData.setRefreshTokenExpiresAt(tokenData.refreshTokenExpiresAt());

        profileViewData.setScopes(tokenData.scopes());
        profileViewData.setLastUpdatedAt(tokenData.savedAt());
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
        String accessToken = profileViewData.getAccessToken();
        String idToken = profileViewData.getIdToken();

        Map<String, Object> accessTokenPayload =
                jwtPayloadDecoder.decodePayload(accessToken);

        Map<String, Object> idTokenPayload =
                jwtPayloadDecoder.decodePayload(idToken);

        profileViewData.setAccessTokenPayload(accessTokenPayload);
        profileViewData.setIdTokenPayload(idTokenPayload);

        profileViewData.setAccessTokenJti(
                getStringClaim(accessTokenPayload, "jti")
        );

        profileViewData.setIdTokenJti(
                getStringClaim(idTokenPayload, "jti")
        );

        if (profileViewData.getSubject() == null) {
            profileViewData.setSubject(getStringClaim(idTokenPayload, "sub"));
        }

        if (profileViewData.getEmail() == null) {
            profileViewData.setEmail(getStringClaim(idTokenPayload, "email"));
        }

        if (profileViewData.getDisplayName() == null) {
            String name = getStringClaim(idTokenPayload, "name");

            if (name == null) {
                name = getStringClaim(idTokenPayload, "preferred_username");
            }

            profileViewData.setDisplayName(name);
        }
    }

    private String getStringClaim(Map<String, Object> payload, String claimName) {
        if (payload == null || payload.isEmpty()) {
            return null;
        }

        Object value = payload.get(claimName);

        if (value == null) {
            return null;
        }

        return String.valueOf(value);
    }
}