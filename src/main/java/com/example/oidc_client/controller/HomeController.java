package com.example.oidc_client.controller;

import com.example.oidc_client.dto.ProfileViewData;
import com.example.oidc_client.service.ProfileService;
import com.example.oidc_client.storage.AuthTokenStorageService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private static final String REGISTRATION_ID = "autoriza";

    private final ProfileService profileService;
    private final AuthTokenStorageService tokenStorageService;

    public HomeController(
            ProfileService profileService,
            AuthTokenStorageService tokenStorageService
    ) {
        this.profileService = profileService;
        this.tokenStorageService = tokenStorageService;
    }

    @GetMapping("/")
    public String home(
            Authentication authentication,
            HttpServletRequest request,
            Model model
    ) {
        boolean authenticated = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(String.valueOf(authentication.getPrincipal()));

        boolean skipRestore = request.getParameter("skipRestore") != null;

        if (!authenticated
                && !skipRestore
                && tokenStorageService.existsByRegistrationId(REGISTRATION_ID)) {
            return "redirect:/restore-session";
        }

        model.addAttribute("authenticated", authenticated);

        if (authenticated) {
            model.addAttribute("principalName", authentication.getName());
        }

        model.addAttribute(
                "hasStoredSession",
                tokenStorageService.existsByRegistrationId(REGISTRATION_ID)
        );

        return "index";
    }

    @GetMapping("/profile")
    public String profile(
            Authentication authentication,
            HttpServletRequest request,
            Model model
    ) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/";
        }

        ProfileViewData profile = profileService.buildProfileViewData(
                authentication,
                request
        );

        model.addAttribute("profile", profile);

        model.addAttribute("principalName", profile.getPrincipalName());
        model.addAttribute("displayName", profile.getDisplayName());
        model.addAttribute("email", profile.getEmail());
        model.addAttribute("subject", profile.getSubject());

        model.addAttribute("clientRegistrationId", profile.getClientRegistrationId());
        model.addAttribute("tokenType", profile.getTokenType());

        model.addAttribute("accessToken", profile.getAccessToken());
        model.addAttribute("maskedAccessToken", profile.getMaskedAccessToken());
        model.addAttribute("refreshToken", profile.getRefreshToken());
        model.addAttribute("maskedRefreshToken", profile.getMaskedRefreshToken());
        model.addAttribute("idToken", profile.getIdToken());
        model.addAttribute("maskedIdToken", profile.getMaskedIdToken());

        model.addAttribute("accessTokenIssuedAt", profile.getAccessTokenIssuedAt());
        model.addAttribute("accessTokenExpiresAt", profile.getAccessTokenExpiresAt());
        model.addAttribute("refreshTokenIssuedAt", profile.getRefreshTokenIssuedAt());
        model.addAttribute("refreshTokenExpiresAt", profile.getRefreshTokenExpiresAt());

        model.addAttribute("scopes", profile.getScopes());

        model.addAttribute("accessTokenPayload", profile.getAccessTokenPayload());
        model.addAttribute("idTokenPayload", profile.getIdTokenPayload());

        model.addAttribute("accessTokenJti", profile.getAccessTokenJti());
        model.addAttribute("idTokenJti", profile.getIdTokenJti());
        model.addAttribute("sameJti", profile.isSameJti());

        model.addAttribute("accessTokenPresent", profile.isAccessTokenPresent());
        model.addAttribute("refreshTokenPresent", profile.isRefreshTokenPresent());
        model.addAttribute("idTokenPresent", profile.isIdTokenPresent());

        model.addAttribute("lastUpdatedAt", profile.getLastUpdatedAt());

        return "profile";
    }
}