package com.example.oidc_client.service;

import com.example.oidc_client.dto.TokenEndpointResponse;
import com.example.oidc_client.util.TokenScopeParser;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Service
public class TokenEndpointClient {

    private final RestClient restClient;
    private final TokenScopeParser tokenScopeParser;

    public TokenEndpointClient(TokenScopeParser tokenScopeParser) {
        this.restClient = RestClient.create();
        this.tokenScopeParser = tokenScopeParser;
    }

    public TokenEndpointResponse refreshToken(
            ClientRegistration clientRegistration,
            String refreshTokenValue
    ) {
        if (clientRegistration == null) {
            throw new IllegalArgumentException(
                    "Client registration must not be null"
            );
        }

        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            throw new IllegalArgumentException(
                    "Refresh token must not be blank"
            );
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshTokenValue);

        Map<String, Object> response = restClient.post()
                .uri(clientRegistration.getProviderDetails().getTokenUri())
                .headers(headers -> headers.setBasicAuth(
                        clientRegistration.getClientId(),
                        clientRegistration.getClientSecret()
                ))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });

        if (response == null) {
            throw new IllegalStateException(
                    "Token Endpoint returned empty response"
            );
        }

        String scope = getStringValue(response, "scope");
        Set<String> scopes = tokenScopeParser.parse(scope);

        return new TokenEndpointResponse(
                getStringValue(response, "access_token"),
                getStringValue(response, "refresh_token"),
                getStringValue(response, "id_token"),
                getStringValue(response, "token_type"),
                getIntegerValue(response, "expires_in"),
                scope,
                scopes,
                Instant.now()
        );
    }

    private String getStringValue(
            Map<String, Object> response,
            String key
    ) {
        Object value = response.get(key);

        if (value == null) {
            return null;
        }

        return String.valueOf(value);
    }

    private Integer getIntegerValue(
            Map<String, Object> response,
            String key
    ) {
        Object value = response.get(key);

        if (value == null) {
            return null;
        }

        if (value instanceof Number number) {
            return number.intValue();
        }

        if (value instanceof String stringValue && !stringValue.isBlank()) {
            return Integer.parseInt(stringValue);
        }

        return null;
    }
}