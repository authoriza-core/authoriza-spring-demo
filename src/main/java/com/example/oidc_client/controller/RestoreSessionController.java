package com.example.oidc_client.controller;

import com.example.oidc_client.service.SessionRestoreService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RestoreSessionController {

    private final SessionRestoreService sessionRestoreService;

    public RestoreSessionController(SessionRestoreService sessionRestoreService) {
        this.sessionRestoreService = sessionRestoreService;
    }

    @GetMapping("/restore-session")
    public String restoreSession(
            HttpServletRequest request,
            HttpServletResponse response) {
        boolean restored = sessionRestoreService.restore(request, response);

        if (restored) {
            return "redirect:/profile?restored=true";
        }

        return "redirect:/?skipRestore=true";
    }
}