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
                && !"anonymousUser".equals(
                        String.valueOf(authentication.getPrincipal())
                );

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

        model.addAttribute(
                "principalName",
                profile.getUser().getPrincipalName()
        );
        model.addAttribute(
                "displayName",
                profile.getUser().getDisplayName()
        );
        model.addAttribute(
                "email",
                profile.getUser().getEmail()
        );
        model.addAttribute(
                "subject",
                profile.getUser().getSubject()
        );
        model.addAttribute(
                "clientRegistrationId",
                profile.getUser().getClientRegistrationId()
        );

        model.addAttribute(
                "tokenType",
                profile.getRawTokens().getTokenType()
        );

        model.addAttribute(
                "accessToken",
                profile.getRawTokens().getAccessToken()
        );
        model.addAttribute(
                "maskedAccessToken",
                profile.getRawTokens().getMaskedAccessToken()
        );
        model.addAttribute(
                "refreshToken",
                profile.getRawTokens().getRefreshToken()
        );
        model.addAttribute(
                "maskedRefreshToken",
                profile.getRawTokens().getMaskedRefreshToken()
        );
        model.addAttribute(
                "idToken",
                profile.getRawTokens().getIdToken()
        );
        model.addAttribute(
                "maskedIdToken",
                profile.getRawTokens().getMaskedIdToken()
        );

        model.addAttribute(
                "accessTokenIssuedAt",
                profile.getRawTokens().getAccessTokenIssuedAt()
        );
        model.addAttribute(
                "accessTokenExpiresAt",
                profile.getRawTokens().getAccessTokenExpiresAt()
        );
        model.addAttribute(
                "refreshTokenIssuedAt",
                profile.getRawTokens().getRefreshTokenIssuedAt()
        );
        model.addAttribute(
                "refreshTokenExpiresAt",
                profile.getRawTokens().getRefreshTokenExpiresAt()
        );
        model.addAttribute(
                "accessTokenExpiresIn",
                profile.getRawTokens().getAccessTokenExpiresIn()
        );

        model.addAttribute(
                "scopes",
                profile.getRawTokens().getScopes()
        );

        model.addAttribute(
                "accessTokenPayload",
                profile.getParsedTokens().getAccessTokenPayload()
        );
        model.addAttribute(
                "idTokenPayload",
                profile.getParsedTokens().getIdTokenPayload()
        );

        model.addAttribute(
                "accessTokenJti",
                profile.getParsedTokens().getAccessTokenJti()
        );
        model.addAttribute(
                "idTokenJti",
                profile.getParsedTokens().getIdTokenJti()
        );

        model.addAttribute(
                "sameJti",
                profile.getValidation().isSameJti()
        );

        model.addAttribute(
                "accessTokenPresent",
                profile.getValidation().isAccessTokenPresent()
        );
        model.addAttribute(
                "refreshTokenPresent",
                profile.getValidation().isRefreshTokenPresent()
        );
        model.addAttribute(
                "idTokenPresent",
                profile.getValidation().isIdTokenPresent()
        );

        model.addAttribute(
                "lastUpdatedAt",
                profile.getValidation().getLastUpdatedAt()
        );

        return "profile";
    }
}