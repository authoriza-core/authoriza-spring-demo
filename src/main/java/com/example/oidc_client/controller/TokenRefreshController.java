package com.example.oidc_client.controller;

import com.example.oidc_client.dto.TokenRefreshResult;
import com.example.oidc_client.dto.TokenSet;
import com.example.oidc_client.service.TokenRefreshService;
import com.example.oidc_client.util.TokenMasker;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class TokenRefreshController {

    private final TokenRefreshService tokenRefreshService;
    private final TokenMasker tokenMasker;

    public TokenRefreshController(
            TokenRefreshService tokenRefreshService,
            TokenMasker tokenMasker
    ) {
        this.tokenRefreshService = tokenRefreshService;
        this.tokenMasker = tokenMasker;
    }

    @PostMapping("/refresh-token")
    public String refreshToken(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        TokenRefreshResult result = tokenRefreshService.refresh(
                authentication,
                request,
                response
        );

        model.addAttribute("result", result);
        model.addAttribute("success", result.success());
        model.addAttribute("message", result.message());
        model.addAttribute("errorCode", result.errorCode());
        model.addAttribute("refreshedAt", result.refreshedAt());

        TokenSet tokenSet = result.tokenSet();

        if (tokenSet != null) {
            model.addAttribute("accessToken", tokenSet.accessTokenValue());
            model.addAttribute("refreshToken", tokenSet.refreshTokenValue());
            model.addAttribute("idToken", tokenSet.idTokenValue());

            model.addAttribute(
                    "maskedAccessToken",
                    tokenMasker.mask(tokenSet.accessTokenValue())
            );

            model.addAttribute(
                    "maskedRefreshToken",
                    tokenMasker.mask(tokenSet.refreshTokenValue())
            );

            model.addAttribute(
                    "maskedIdToken",
                    tokenMasker.mask(tokenSet.idTokenValue())
            );

            model.addAttribute("tokenType", tokenSet.tokenType());

            model.addAttribute("accessTokenIssuedAt", tokenSet.accessTokenIssuedAt());
            model.addAttribute("accessTokenExpiresAt", tokenSet.accessTokenExpiresAt());
            model.addAttribute("refreshTokenIssuedAt", tokenSet.refreshTokenIssuedAt());
            model.addAttribute("refreshTokenExpiresAt", tokenSet.refreshTokenExpiresAt());

            model.addAttribute("scopes", tokenSet.scopes());
        }

        if (result.success()) {
            return "refresh-result";
        }

        return "refresh-error";
    }
}