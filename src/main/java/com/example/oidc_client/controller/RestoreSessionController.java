package com.example.oidc_client.controller;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.storage.StoredAuthData;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class RestoreSessionController {

    private final AuthTokenStorageService tokenStorageService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    public RestoreSessionController(
            AuthTokenStorageService tokenStorageService,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
        this.tokenStorageService = tokenStorageService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        this.restClient = RestClient.create();
        this.objectMapper = new ObjectMapper();
    }

    @GetMapping("/restore-session")
    public String restoreSession(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            StoredAuthData storedAuthData = tokenStorageService.findByRegistrationId("autoriza");

            if (storedAuthData == null || storedAuthData.getRefreshToken() == null) {
                return "redirect:/";
            }

            ClientRegistration clientRegistration =
                    clientRegistrationRepository.findByRegistrationId("autoriza");

            Map<String, Object> tokenResponse = refreshTokens(clientRegistration, storedAuthData.getRefreshToken());

            String accessTokenValue = tokenResponse.get("access_token").toString();
            String refreshTokenValue = tokenResponse.get("refresh_token") != null
                    ? tokenResponse.get("refresh_token").toString()
                    : storedAuthData.getRefreshToken();
            String idTokenValue = tokenResponse.get("id_token") != null
                    ? tokenResponse.get("id_token").toString()
                    : storedAuthData.getIdToken();

            long expiresIn = getLongValue(tokenResponse, "expires_in", 3600);

            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(expiresIn);

            Set<String> scopes = parseScopes(tokenResponse.get("scope"));

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    accessTokenValue,
                    issuedAt,
                    expiresAt,
                    scopes
            );

            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    refreshTokenValue,
                    issuedAt
            );

            OidcIdToken idToken = buildIdToken(idTokenValue);

            Set<GrantedAuthority> authorities = new HashSet<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            OidcUser oidcUser = new DefaultOidcUser(
                    authorities,
                    idToken,
                    "sub"
            );

            OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                    oidcUser,
                    authorities,
                    "autoriza"
            );

            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            request.getSession(true).setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    authentication.getName(),
                    accessToken,
                    refreshToken
            );

            authorizedClientRepository.saveAuthorizedClient(
                    updatedClient,
                    authentication,
                    request,
                    response
            );

            tokenStorageService.saveTokens(
                    "autoriza",
                    authentication.getName(),
                    accessTokenValue,
                    refreshTokenValue,
                    idTokenValue,
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt(),
                    refreshToken.getIssuedAt(),
                    idToken.getIssuedAt(),
                    idToken.getExpiresAt(),
                    accessToken.getScopes()
            );

            request.getSession().setAttribute("latestIdToken", idTokenValue);

            return "redirect:/profile";

        } catch (Exception exception) {
            exception.printStackTrace();
            return "redirect:/";
        }
    }

    private Map<String, Object> refreshTokens(
            ClientRegistration clientRegistration,
            String refreshToken
    ) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();

        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("client_id", clientRegistration.getClientId());
        form.add("client_secret", clientRegistration.getClientSecret());

        return restClient.post()
                .uri(clientRegistration.getProviderDetails().getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {});
    }

    private OidcIdToken buildIdToken(String idTokenValue) throws Exception {
        Map<String, Object> claims = decodeJwtPayload(idTokenValue);

        Instant issuedAt = getInstantClaim(claims, "iat");
        Instant expiresAt = getInstantClaim(claims, "exp");

        return new OidcIdToken(
                idTokenValue,
                issuedAt,
                expiresAt,
                claims
        );
    }

    private Map<String, Object> decodeJwtPayload(String token) throws Exception {
        String[] parts = token.split("\\.");
        byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);
        String payload = new String(decodedBytes, StandardCharsets.UTF_8);

        return objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {});
    }

    private Instant getInstantClaim(Map<String, Object> claims, String key) {
        Object value = claims.get(key);

        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }

        if (value instanceof String stringValue) {
            return Instant.ofEpochSecond(Long.parseLong(stringValue));
        }

        return Instant.now();
    }

    private long getLongValue(Map<String, Object> map, String key, long defaultValue) {
        Object value = map.get(key);

        if (value instanceof Number number) {
            return number.longValue();
        }

        if (value instanceof String stringValue) {
            return Long.parseLong(stringValue);
        }

        return defaultValue;
    }

    private Set<String> parseScopes(Object scopeValue) {
        Set<String> scopes = new HashSet<>();

        if (scopeValue == null) {
            return scopes;
        }

        String[] scopeParts = scopeValue.toString().split(" ");

        for (String scope : scopeParts) {
            if (!scope.isBlank()) {
                scopes.add(scope);
            }
        }

        return scopes;
    }
}