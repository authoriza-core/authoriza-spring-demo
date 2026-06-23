package com.example.oidc_client.controller;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import jakarta.servlet.http.HttpSession;

@Controller
public class UserInfoController {

    private final RestClient restClient;

    public UserInfoController() {
        this.restClient = RestClient.create();
    }

    @GetMapping("/userinfo")
    public String userInfo(
            @AuthenticationPrincipal OidcUser oidcUser,
            @RegisteredOAuth2AuthorizedClient("autoriza") OAuth2AuthorizedClient authorizedClient,
            HttpSession session,
            Model model
    ) {
        if (authorizedClient == null) {
            model.addAttribute("success", false);
            model.addAttribute("message", "OAuth2AuthorizedClient отсутствует. Пользователь не авторизован.");
            addIdTokenClaims(model, oidcUser);
            return "userinfo";
        }

        if (authorizedClient.getAccessToken() == null) {
            model.addAttribute("success", false);
            model.addAttribute("message", "Access Token отсутствует. Невозможно получить UserInfo.");
            addIdTokenClaims(model, oidcUser);
            return "userinfo";
        }

        String userInfoUri = authorizedClient
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUri();

        String accessTokenValue = authorizedClient.getAccessToken().getTokenValue();
        String idTokenValue = getCurrentIdToken(oidcUser, session);

        LocalDateTime receivedAt = LocalDateTime.now();
        Instant currentInstant = Instant.now();
        Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();

        model.addAttribute("userInfoUri", userInfoUri);
        model.addAttribute("receivedAt", receivedAt);
        model.addAttribute("currentInstant", currentInstant);
        model.addAttribute("accessTokenExpiresAt", expiresAt);
        model.addAttribute("accessTokenScopes", authorizedClient.getAccessToken().getScopes());

        addAccessTokenStatus(model, currentInstant, expiresAt);
        addIdTokenClaims(model, oidcUser);

        try {
            Map<String, Object> userInfoResponse = requestUserInfo(userInfoUri, accessTokenValue);

            model.addAttribute("success", true);
            model.addAttribute("message", "UserInfo успешно получен через Access Token.");
            model.addAttribute("usedTokenType", "access_token");
            model.addAttribute("userInfoResponse", userInfoResponse);

            return "userinfo";

        } catch (RestClientResponseException accessTokenException) {
            model.addAttribute("accessTokenStatusCode", accessTokenException.getStatusCode().toString());
            model.addAttribute("accessTokenResponseBody", accessTokenException.getResponseBodyAsString());

            try {
                if (idTokenValue == null || idTokenValue.isBlank()) {
                    model.addAttribute("success", false);
                    model.addAttribute("message", "Access Token не принят UserInfo Endpoint, а ID Token отсутствует.");
                    model.addAttribute("statusCode", accessTokenException.getStatusCode().toString());
                    model.addAttribute("responseBody", accessTokenException.getResponseBodyAsString());
                    return "userinfo";
                }

                Map<String, Object> userInfoResponse = requestUserInfo(userInfoUri, idTokenValue);

                model.addAttribute("success", true);
                model.addAttribute("message", "UserInfo успешно получен через ID Token. Важно: это нестандартное поведение провайдера.");
                model.addAttribute("usedTokenType", "id_token");
                model.addAttribute("userInfoResponse", userInfoResponse);

                return "userinfo";

            } catch (RestClientResponseException idTokenException) {
                model.addAttribute("success", false);
                model.addAttribute("message", "UserInfo Endpoint не принял ни Access Token, ни ID Token.");
                model.addAttribute("usedTokenType", "access_token и id_token");
                model.addAttribute("statusCode", idTokenException.getStatusCode().toString());
                model.addAttribute("responseBody", idTokenException.getResponseBodyAsString());

                return "userinfo";
            }

        } catch (Exception exception) {
            exception.printStackTrace();

            model.addAttribute("success", false);
            model.addAttribute("message", "Внутренняя ошибка при получении UserInfo.");
            model.addAttribute("statusCode", "500");
            model.addAttribute("responseBody", exception.getClass().getName() + ": " + exception.getMessage());

            return "userinfo";
        }
    }

    private Map<String, Object> requestUserInfo(String userInfoUri, String tokenValue) {
        return restClient.get()
                .uri(userInfoUri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenValue)
                .retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {});
    }

    private String getCurrentIdToken(OidcUser oidcUser, HttpSession session) {
        Object latestIdToken = session.getAttribute("latestIdToken");

        if (latestIdToken != null) {
            return latestIdToken.toString();
        }

        if (oidcUser != null && oidcUser.getIdToken() != null) {
            return oidcUser.getIdToken().getTokenValue();
        }

        return "";
    }

    private void addAccessTokenStatus(Model model, Instant currentInstant, Instant expiresAt) {
        if (expiresAt == null) {
            model.addAttribute("accessTokenExpiresIn", "Неизвестно");
            model.addAttribute("accessTokenStatus", "Не удалось определить срок действия Access Token.");
            return;
        }

        long expiresInSeconds = Duration.between(currentInstant, expiresAt).getSeconds();

        model.addAttribute("accessTokenExpiresIn", expiresInSeconds + " секунд");

        if (expiresInSeconds > 0) {
            model.addAttribute("accessTokenStatus", "Access Token ещё действителен.");
        } else {
            model.addAttribute("accessTokenStatus", "Access Token уже истёк.");
        }
    }

    private void addIdTokenClaims(Model model, OidcUser oidcUser) {
        if (oidcUser == null) {
            model.addAttribute("idTokenUserDataAvailable", false);
            model.addAttribute("idTokenUserDataMessage", "Данные из ID Token недоступны, потому что OidcUser отсутствует.");
            return;
        }

        model.addAttribute("idTokenUserDataAvailable", true);
        model.addAttribute("idTokenUserDataMessage", "Данные пользователя получены из ID Token.");
        model.addAttribute("idTokenSubject", oidcUser.getSubject());
        model.addAttribute("idTokenName", oidcUser.getClaims().get("name"));
        model.addAttribute("idTokenEmail", oidcUser.getClaims().get("email"));
        model.addAttribute("idTokenClaims", oidcUser.getClaims());
    }
}