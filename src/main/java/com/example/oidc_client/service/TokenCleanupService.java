package com.example.oidc_client.service;

import com.example.oidc_client.storage.AuthTokenStorageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class TokenCleanupService {

    private static final String DEFAULT_REGISTRATION_ID = "autoriza";

    private final AuthTokenStorageService tokenStorageService;

    public TokenCleanupService(AuthTokenStorageService tokenStorageService) {
        this.tokenStorageService = tokenStorageService;
    }

    public void clearDefaultAuthorization(HttpServletRequest request) {
        clearAuthorization(DEFAULT_REGISTRATION_ID, request);
    }

    public void clearAuthorization(
            String registrationId,
            HttpServletRequest request
    ) {
        if (registrationId != null && !registrationId.isBlank()) {
            tokenStorageService.deleteByRegistrationId(registrationId);
        }

        SecurityContextHolder.clearContext();

        if (request == null) {
            return;
        }

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }
    }

    public void clearAllAuthorizations(HttpServletRequest request) {
        tokenStorageService.deleteAllTokens();
        SecurityContextHolder.clearContext();

        if (request == null) {
            return;
        }

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }
    }
}