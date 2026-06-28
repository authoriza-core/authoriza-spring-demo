
package com.example.oidc_client.controller;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.storage.StoredAuthData;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class TokenRefreshController {

    private static final String REGISTRATION_ID = "autoriza";
    private static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofMinutes(15);

    private final RestClient restClient;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AuthTokenStorageService tokenStorageService;

    public TokenRefreshController(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            AuthTokenStorageService tokenStorageService
    ) {
        this.restClient = RestClient.create();
        this.authorizedClientRepository = authorizedClientRepository;
        this.tokenStorageService = tokenStorageService;
    }

    @PostMapping("/refresh-token")
    public String refreshToken(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        try {
            //Получаем текущего OAuth2-клиента из сессии
            OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                    REGISTRATION_ID,
                    authentication,
                    request
            );

            //Проверяем наличие клиента
            if (authorizedClient == null) {
                model.addAttribute("success", false);
                model.addAttribute("message", "OAuth2AuthorizedClient не найден в сессии.");
                return "refresh-result";
            }

            //Проверяем наличие refresh token
            OAuth2RefreshToken oldRefreshToken = authorizedClient.getRefreshToken();

            if (oldRefreshToken == null) {
                model.addAttribute("success", false);
                model.addAttribute("message", "Refresh Token отсутствует. Обновить токены невозможно.");
                return "refresh-result";
            }

            StoredAuthData storedAuthData = tokenStorageService.findByRegistrationId(REGISTRATION_ID);

            //Проверяем, не истек ли сохраненный refresh token
            if (storedAuthData != null
                    && storedAuthData.getRefreshTokenExpiresAt() != null
                    && !storedAuthData.getRefreshTokenExpiresAt().isAfter(Instant.now())) {

                tokenStorageService.deleteByRegistrationId(REGISTRATION_ID);

                request.getSession().invalidate();

                return "redirect:/oauth2/authorization/" + REGISTRATION_ID;
            }

            //Получаем параметры клиента и Token Endpoint
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

            String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
            String clientId = clientRegistration.getClientId();
            String clientSecret = clientRegistration.getClientSecret();
            String oldRefreshTokenValue = oldRefreshToken.getTokenValue();

            //Формируем запрос на обновление токенов
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", oldRefreshTokenValue);
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);

            //Отправляем запрос в Token Endpoint
            Map<String, Object> tokenResponse = restClient.post()
                    .uri(tokenUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(new ParameterizedTypeReference<Map<String, Object>>() {});

            //Проверяем наличие нового access token
            if (tokenResponse == null || tokenResponse.get("access_token") == null) {
                model.addAttribute("success", false);
                model.addAttribute("message", "Token Endpoint не вернул новый access_token.");
                model.addAttribute("tokenEndpointResponse", "Token Endpoint не вернул access_token. Полный ответ не выводится.");

                return "refresh-result";
            }

            String newAccessTokenValue = tokenResponse.get("access_token").toString();

            String newRefreshTokenValue = oldRefreshTokenValue;
            boolean refreshTokenRotated = false;

            if (tokenResponse.get("refresh_token") != null) {
                newRefreshTokenValue = tokenResponse.get("refresh_token").toString();
                refreshTokenRotated = !newRefreshTokenValue.equals(oldRefreshTokenValue);
            }

            String newIdTokenValue = getCurrentIdTokenValue(tokenResponse, request, storedAuthData);

            long expiresIn = getLongValue(tokenResponse, "expires_in", 3600);

            Instant issuedAt = Instant.now();
            Instant accessTokenExpiresAt = issuedAt.plusSeconds(expiresIn);

            Set<String> scopes = parseScopes(tokenResponse.get("scope"));

            if (scopes.isEmpty() && authorizedClient.getAccessToken() != null) {
                scopes = authorizedClient.getAccessToken().getScopes();
            }

            //Создаем новый Access Token
            OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    newAccessTokenValue,
                    issuedAt,
                    accessTokenExpiresAt,
                    scopes
            );

            Instant refreshTokenIssuedAt = refreshTokenRotated
                    ? issuedAt
                    : oldRefreshToken.getIssuedAt();

            if (refreshTokenIssuedAt == null) {
                refreshTokenIssuedAt = issuedAt;
            }

            Instant refreshTokenExpiresAt = calculateRefreshTokenExpiresAt(
                    storedAuthData,
                    refreshTokenRotated,
                    refreshTokenIssuedAt
            );

            //Создаем новый Refresh Token
            OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                    newRefreshTokenValue,
                    refreshTokenIssuedAt
            );

            //Создаем обновленного OAuth2-клиента
            OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    authorizedClient.getPrincipalName(),
                    newAccessToken,
                    newRefreshToken
            );

            //Сохраняем обновленные токены в сессии
            authorizedClientRepository.saveAuthorizedClient(
                    updatedClient,
                    authentication,
                    request,
                    response
            );

            request.getSession().setAttribute("latestIdToken", newIdTokenValue);

            //Сохраняем обновленные токены в H2
            tokenStorageService.saveTokens(
                    REGISTRATION_ID,
                    authorizedClient.getPrincipalName(),
                    newAccessTokenValue,
                    newRefreshTokenValue,
                    newIdTokenValue,
                    issuedAt,
                    accessTokenExpiresAt,
                    refreshTokenIssuedAt,
                    refreshTokenExpiresAt,
                    storedAuthData != null ? storedAuthData.getIdTokenIssuedAt() : null,
                    storedAuthData != null ? storedAuthData.getIdTokenExpiresAt() : null,
                    scopes
            );

            //Передаем результат обновления на страницу
            model.addAttribute("success", true);
            model.addAttribute("message", "Токены успешно обновлены и сохранены в сессии и H2.");
            model.addAttribute("newAccessToken", maskToken(newAccessTokenValue));
            model.addAttribute("newRefreshToken", maskToken(newRefreshTokenValue));
            model.addAttribute("newIdToken", maskToken(newIdTokenValue));

            model.addAttribute("tokenType", tokenResponse.get("token_type"));
            model.addAttribute("scope", scopes);
            model.addAttribute("expiresIn", expiresIn);
            model.addAttribute("expiresAt", accessTokenExpiresAt);
            model.addAttribute("refreshTokenIssuedAt", refreshTokenIssuedAt);
            model.addAttribute("refreshTokenExpiresAt", refreshTokenExpiresAt);

            model.addAttribute(
                    "tokenEndpointResponse",
                    "Token Endpoint вернул новые токены. Полный ответ скрыт, потому что содержит секретные значения."
            );

            return "refresh-result";

        } catch (RestClientResponseException exception) {
            //Обрабатываем ошибку от Token Endpoint
            model.addAttribute("success", false);
            model.addAttribute("message", "Ошибка при запросе к Token Endpoint.");
            model.addAttribute("statusCode", exception.getStatusCode().toString());
            model.addAttribute("responseBody", exception.getResponseBodyAsString());

            return "refresh-result";

        } catch (Exception exception) {
            //Обрабатываем внутреннюю ошибку приложения
            exception.printStackTrace();

            model.addAttribute("success", false);
            model.addAttribute("message", "Внутренняя ошибка при обновлении токенов.");
            model.addAttribute("statusCode", "500");
            model.addAttribute("responseBody", exception.getClass().getName() + ": " + exception.getMessage());

            return "refresh-result";
        }
    }

    private String getCurrentIdTokenValue(
            Map<String, Object> tokenResponse,
            HttpServletRequest request,
            StoredAuthData storedAuthData
    ) {
        if (tokenResponse.get("id_token") != null) {
            return tokenResponse.get("id_token").toString();
        }

        Object latestIdToken = request.getSession().getAttribute("latestIdToken");

        if (latestIdToken != null) {
            return latestIdToken.toString();
        }

        if (storedAuthData != null && storedAuthData.getIdToken() != null) {
            return storedAuthData.getIdToken();
        }

        return "";
    }

    private Instant calculateRefreshTokenExpiresAt(
            StoredAuthData storedAuthData,
            boolean refreshTokenRotated,
            Instant refreshTokenIssuedAt
    ) {
        if (!refreshTokenRotated
                && storedAuthData != null
                && storedAuthData.getRefreshTokenExpiresAt() != null) {
            return storedAuthData.getRefreshTokenExpiresAt();
        }

        return refreshTokenIssuedAt.plus(REFRESH_TOKEN_LIFETIME);
    }


    private String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "Токен отсутствует";
        }

        if (token.length() <= 16) {
            return "***";
        }

        return token.substring(0, 10) + "..." + token.substring(token.length() - 6);
    }

    private long getLongValue(Map<String, Object> map, String key, long defaultValue) {
        Object value = map.get(key);

        //Преобразуем число из ответа Token Endpoint
        if (value instanceof Number number) {
            return number.longValue();
        }

        //Преобразуем строку в число
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
