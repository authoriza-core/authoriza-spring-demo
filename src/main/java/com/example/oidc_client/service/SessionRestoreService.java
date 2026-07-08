package com.example.oidc_client.service;

import com.example.oidc_client.dto.StoredTokenData;
import com.example.oidc_client.dto.TokenEndpointResponse;
import com.example.oidc_client.dto.TokenSet;
import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.util.JwtPayloadDecoder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
public class SessionRestoreService {

    private static final String REGISTRATION_ID = "autoriza";

    private final AuthTokenStorageService tokenStorageService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final TokenEndpointClient tokenEndpointClient;
    private final OAuth2AuthorizedClientFacade authorizedClientService;
    private final JwtPayloadDecoder jwtPayloadDecoder;

    public SessionRestoreService(
            AuthTokenStorageService tokenStorageService,
            ClientRegistrationRepository clientRegistrationRepository,
            TokenEndpointClient tokenEndpointClient,
            OAuth2AuthorizedClientFacade authorizedClientService,
            JwtPayloadDecoder jwtPayloadDecoder
    ) {
        this.tokenStorageService = tokenStorageService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.tokenEndpointClient = tokenEndpointClient;
        this.authorizedClientService = authorizedClientService;
        this.jwtPayloadDecoder = jwtPayloadDecoder;
    }

    public boolean restore(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            Optional<StoredTokenData> storedTokenDataOptional =
                    tokenStorageService.findByRegistrationId(REGISTRATION_ID);

            if (storedTokenDataOptional.isEmpty()) {
                return false;
            }

            StoredTokenData storedTokenData = storedTokenDataOptional.get();

            if (!storedTokenData.hasRefreshToken()) {
                return false;
            }

            ClientRegistration clientRegistration =
                    clientRegistrationRepository.findByRegistrationId(
                            REGISTRATION_ID
                    );

            if (clientRegistration == null) {
                return false;
            }

            TokenEndpointResponse tokenEndpointResponse =
                    tokenEndpointClient.refreshToken(
                            clientRegistration,
                            storedTokenData.refreshTokenValue()
                    );

            if (!tokenEndpointResponse.hasAccessToken()) {
                return false;
            }

            String refreshTokenValue = tokenEndpointResponse.hasRefreshToken()
                    ? tokenEndpointResponse.refreshToken()
                    : storedTokenData.refreshTokenValue();

            String idTokenValue = tokenEndpointResponse.hasIdToken()
                    ? tokenEndpointResponse.idToken()
                    : storedTokenData.idTokenValue();

            if (idTokenValue == null || idTokenValue.isBlank()) {
                return false;
            }

            Set<String> scopes = tokenEndpointResponse.scopes().isEmpty()
                    ? storedTokenData.scopes()
                    : tokenEndpointResponse.scopes();

            Instant accessTokenIssuedAt =
                    tokenEndpointResponse.accessTokenIssuedAt();

            TokenSet tokenSet = new TokenSet(
                    tokenEndpointResponse.accessToken(),
                    refreshTokenValue,
                    idTokenValue,
                    tokenEndpointResponse.tokenType() == null
                            ? "Bearer"
                            : tokenEndpointResponse.tokenType(),
                    accessTokenIssuedAt,
                    tokenEndpointResponse.accessTokenExpiresAt(),
                    accessTokenIssuedAt,
                    null,
                    scopes
            );

            OidcIdToken idToken = buildIdToken(idTokenValue);
            Set<GrantedAuthority> authorities = new HashSet<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            OidcUser oidcUser = new DefaultOidcUser(
                    authorities,
                    idToken,
                    "sub"
            );

            OAuth2AuthenticationToken authentication =
                    new OAuth2AuthenticationToken(
                            oidcUser,
                            authorities,
                            REGISTRATION_ID
                    );

            SecurityContext securityContext =
                    SecurityContextHolder.createEmptyContext();

            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            request.getSession(true).setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            OAuth2AuthorizedClient authorizedClient =
                    authorizedClientService.buildAuthorizedClient(
                            clientRegistration,
                            authentication.getName(),
                            tokenSet
                    );

            authorizedClientService.saveAuthorizedClient(
                    authorizedClient,
                    authentication,
                    request,
                    response
            );

            tokenStorageService.saveTokenSet(
                    authentication.getName(),
                    REGISTRATION_ID,
                    tokenSet
            );

            request.getSession(true).setAttribute("latestIdToken", idTokenValue);

            return true;
        } catch (Exception exception) {
            SecurityContextHolder.clearContext();
            return false;
        }
    }

    private OidcIdToken buildIdToken(String idTokenValue) {
        Map<String, Object> claims = jwtPayloadDecoder.decodePayload(idTokenValue);

        Instant issuedAt = getInstantClaim(claims, "iat");
        Instant expiresAt = getInstantClaim(claims, "exp");

        return new OidcIdToken(
                idTokenValue,
                issuedAt,
                expiresAt,
                claims
        );
    }

    private Instant getInstantClaim(Map<String, Object> claims, String key) {
        if (claims == null || claims.isEmpty()) {
            return Instant.now();
        }

        Object value = claims.get(key);

        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }

        if (value instanceof String stringValue && !stringValue.isBlank()) {
            return Instant.ofEpochSecond(Long.parseLong(stringValue));
        }

        return Instant.now();
    }
}