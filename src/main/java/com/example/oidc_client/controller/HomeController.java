
package com.example.oidc_client.controller;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.oidc_client.storage.AuthTokenStorageService;
import com.example.oidc_client.storage.StoredAuthData;

@Controller
public class HomeController {

    private static final String REGISTRATION_ID = "autoriza";
    private static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofMinutes(15);

    private final AuthTokenStorageService tokenStorageService;

    public HomeController(AuthTokenStorageService tokenStorageService) {
        this.tokenStorageService = tokenStorageService;
    }

    @GetMapping("/")
    public String index(
            Authentication authentication,
            @RequestParam(name = "skipRestore", defaultValue = "false") boolean skipRestore,
            Model model
    ) {
        if (isAuthenticated(authentication)) {
            return "redirect:/profile";
        }

        if (!skipRestore) {
            StoredAuthData storedAuthData = tokenStorageService.findByRegistrationId(REGISTRATION_ID);

            if (storedAuthData != null) {
                Instant refreshTokenExpiresAt = storedAuthData.getRefreshTokenExpiresAt();

                if (refreshTokenExpiresAt == null || refreshTokenExpiresAt.isAfter(Instant.now())) {
                    return "redirect:/restore-session";
                }

                tokenStorageService.deleteByRegistrationId(REGISTRATION_ID);
            }
        }

        model.addAttribute("authenticated", false);

        return "index";
    }

    @GetMapping("/profile")
    public String profile(
            @AuthenticationPrincipal OidcUser oidcUser,
            @RegisteredOAuth2AuthorizedClient("autoriza") OAuth2AuthorizedClient authorizedClient,
            Model model
    ) {
        try {
            if (oidcUser == null) {
                model.addAttribute("error", "OidcUser отсутствует. Пользователь не авторизован.");
                return "profile";
            }

            if (authorizedClient == null) {
                model.addAttribute("error", "OAuth2AuthorizedClient отсутствует. Токены не найдены.");
                return "profile";
            }

            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

            String idTokenValue = "";
            if (oidcUser.getIdToken() != null) {
                idTokenValue = oidcUser.getIdToken().getTokenValue();
            }

            String accessTokenValue = "";
            if (accessToken != null) {
                accessTokenValue = accessToken.getTokenValue();
            }

            String refreshTokenValue = "";
            if (refreshToken != null) {
                refreshTokenValue = refreshToken.getTokenValue();
            }

            Object name = oidcUser.getClaims().get("name");
            Object email = oidcUser.getClaims().get("email");

            model.addAttribute("userName", name != null ? name.toString() : "Имя не получено");
            model.addAttribute("userEmail", email != null ? email.toString() : "Email не получен");

            if (accessToken != null) {
                model.addAttribute("tokenType", accessToken.getTokenType().getValue());
                model.addAttribute("scopes", accessToken.getScopes());
                model.addAttribute("accessTokenExpiresAt", accessToken.getExpiresAt());
                model.addAttribute("accessTokenExpiresIn", calculateExpiresIn(accessToken.getExpiresAt()));
            } else {
                model.addAttribute("tokenType", "Access Token отсутствует");
                model.addAttribute("scopes", "Scope отсутствует");
                model.addAttribute("accessTokenExpiresAt", "Срок действия неизвестен");
                model.addAttribute("accessTokenExpiresIn", "Неизвестно");
            }

            Instant refreshTokenIssuedAt = null;
            Instant refreshTokenExpiresAt = null;

            if (refreshToken != null) {
                refreshTokenIssuedAt = refreshToken.getIssuedAt();

                StoredAuthData currentStoredAuthData = tokenStorageService.findByRegistrationId(REGISTRATION_ID);

                if (currentStoredAuthData != null && currentStoredAuthData.getRefreshTokenExpiresAt() != null) {
                    refreshTokenExpiresAt = currentStoredAuthData.getRefreshTokenExpiresAt();
                } else {
                    refreshTokenExpiresAt = refreshTokenIssuedAt != null
                            ? refreshTokenIssuedAt.plus(REFRESH_TOKEN_LIFETIME)
                            : Instant.now().plus(REFRESH_TOKEN_LIFETIME);
                }

                model.addAttribute("refreshTokenIssuedAt", refreshTokenIssuedAt);
                model.addAttribute("refreshTokenExpiresAt", refreshTokenExpiresAt);
            } else {
                model.addAttribute("refreshTokenIssuedAt", "Refresh Token отсутствует");
                model.addAttribute("refreshTokenExpiresAt", "Refresh Token отсутствует");
            }

            if (accessToken != null && refreshToken != null) {
                tokenStorageService.saveTokens(
                        REGISTRATION_ID,
                        authorizedClient.getPrincipalName(),
                        accessTokenValue,
                        refreshTokenValue,
                        idTokenValue,
                        accessToken.getIssuedAt(),
                        accessToken.getExpiresAt(),
                        refreshTokenIssuedAt,
                        refreshTokenExpiresAt,
                        oidcUser.getIdToken() != null ? oidcUser.getIdToken().getIssuedAt() : null,
                        oidcUser.getIdToken() != null ? oidcUser.getIdToken().getExpiresAt() : null,
                        accessToken.getScopes()
                );
            }

            StoredAuthData storedAuthData = tokenStorageService.findByRegistrationId(REGISTRATION_ID);

            if (storedAuthData != null) {
                model.addAttribute("lastUpdatedAt", storedAuthData.getLastUpdatedAt());
                model.addAttribute("refreshTokenExpiresAt", storedAuthData.getRefreshTokenExpiresAt());
            }

            model.addAttribute("accessToken", maskToken(accessTokenValue));
            model.addAttribute("idToken", maskToken(idTokenValue));
            model.addAttribute("idTokenPayload", decodeJwtPayloadSafe(idTokenValue));
            model.addAttribute("accessTokenPayload", decodeJwtPayloadSafe(accessTokenValue));

            if (refreshTokenValue.isBlank()) {
                model.addAttribute("refreshToken", "Refresh Token не выдан");
            } else {
                model.addAttribute("refreshToken", maskToken(refreshTokenValue));
            }

            model.addAttribute("accessTokenCompareInfo", getJwtCompareInfo(accessTokenValue));
            model.addAttribute("idTokenCompareInfo", getJwtCompareInfo(idTokenValue));

            return "profile";

        } catch (Exception exception) {
            exception.printStackTrace();

            model.addAttribute("error", exception.getClass().getName() + ": " + exception.getMessage());

            return "profile";
        }
    }

    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private String calculateExpiresIn(Instant expiresAt) {
        if (expiresAt == null) {
            return "Неизвестно";
        }

        long seconds = Duration.between(Instant.now(), expiresAt).getSeconds();

        if (seconds < 0) {
            return "Токен истёк";
        }

        return seconds + " секунд";
    }

    private String decodeJwtPayloadSafe(String token) {
        try {
            if (token == null || token.isBlank()) {
                return "Токен отсутствует";
            }

            String[] parts = token.split("\\.");

            if (parts.length < 2) {
                return "Токен не является JWT или не содержит payload";
            }

            byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);

            return new String(decodedBytes, StandardCharsets.UTF_8);

        } catch (Exception exception) {
            return "Ошибка декодирования JWT payload: " + exception.getMessage();
        }
    }

    private String getJwtCompareInfo(String token) {
        try {
            if (token == null || token.isBlank()) {
                return "Токен отсутствует";
            }

            String[] parts = token.split("\\.");

            if (parts.length < 2) {
                return "Токен не является JWT";
            }

            byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);
            String payload = new String(decodedBytes, StandardCharsets.UTF_8);

            String jti = extractJsonValue(payload, "jti");
            String iat = extractJsonValue(payload, "iat");
            String exp = extractJsonValue(payload, "exp");

            return "jti=" + maskJti(jti) + " | iat=" + iat + " | exp=" + exp;

        } catch (Exception exception) {
            return "Ошибка получения данных для сравнения: " + exception.getMessage();
        }
    }

    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int keyIndex = json.indexOf(searchKey);

        if (keyIndex == -1) {
            return "нет";
        }

        int valueStart = keyIndex + searchKey.length();

        while (valueStart < json.length() && json.charAt(valueStart) == ' ') {
            valueStart++;
        }

        if (valueStart < json.length() && json.charAt(valueStart) == '"') {
            int start = valueStart + 1;
            int end = json.indexOf("\"", start);

            if (end == -1) {
                return "нет";
            }

            return json.substring(start, end);
        }

        int end = valueStart;

        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') {
            end++;
        }

        return json.substring(valueStart, end).trim();
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

    private String maskJti(String jti) {
        if (jti == null || jti.isBlank() || jti.equals("нет")) {
            return "нет";
        }

        if (jti.length() <= 12) {
            return "***";
        }

        return jti.substring(0, 8) + "..." + jti.substring(jti.length() - 4);
    }
}
