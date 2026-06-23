package com.example.oidc_client.controller;

import java.time.Instant;
import java.util.Map;

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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class TokenRefreshController {

    private final RestClient restClient;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    public TokenRefreshController(OAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.restClient = RestClient.create();
        this.authorizedClientRepository = authorizedClientRepository;
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
                    "autoriza",
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
            if (authorizedClient.getRefreshToken() == null) {
                model.addAttribute("success", false);
                model.addAttribute("message", "Refresh Token отсутствует. Обновить токены невозможно.");
                return "refresh-result";
            }

            //Получаем параметры клиента и Token Endpoint
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

            String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
            String clientId = clientRegistration.getClientId();
            String clientSecret = clientRegistration.getClientSecret();
            String refreshTokenValue = authorizedClient.getRefreshToken().getTokenValue();

            //Формируем запрос на обновление токенов
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshTokenValue);
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
                model.addAttribute("tokenEndpointResponse", tokenResponse);
                return "refresh-result";
            }

            //Получаем новые значения токенов
            String newAccessTokenValue = tokenResponse.get("access_token").toString();

            String newRefreshTokenValue = refreshTokenValue;
            if (tokenResponse.get("refresh_token") != null) {
                newRefreshTokenValue = tokenResponse.get("refresh_token").toString();
            }

            long expiresIn = getLongValue(tokenResponse, "expires_in", 3600);

            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(expiresIn);

            //Создаем новый Access Token
            OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    newAccessTokenValue,
                    issuedAt,
                    expiresAt,
                    authorizedClient.getAccessToken().getScopes()
            );

            //Создаем новый Refresh Token
            OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                    newRefreshTokenValue,
                    issuedAt
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

            //Передаем результат обновления на страницу
            model.addAttribute("success", true);
            model.addAttribute("message", "Токены успешно обновлены и сохранены в сессии.");
            model.addAttribute("newAccessToken", maskToken(newAccessTokenValue));
            model.addAttribute("newRefreshToken", maskToken(newRefreshTokenValue));

            model.addAttribute("tokenType", tokenResponse.get("token_type"));
            model.addAttribute("scope", tokenResponse.get("scope"));
            model.addAttribute("expiresIn", expiresIn);
            model.addAttribute("expiresAt", expiresAt);

            model.addAttribute("tokenEndpointResponse", "Token Endpoint вернул новые токены. Полный ответ скрыт, потому что содержит секретные значения.");
            model.addAttribute("expiresIn", expiresIn);
            model.addAttribute("expiresAt", expiresAt);


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
}