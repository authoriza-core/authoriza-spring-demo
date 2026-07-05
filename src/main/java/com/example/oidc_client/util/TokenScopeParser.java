package com.example.oidc_client.util;

import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class TokenScopeParser {

    public Set<String> parse(String scope) {
        if (scope == null || scope.isBlank()) {
            return Collections.emptySet();
        }

        return Arrays.stream(scope.trim().split("\\s+"))
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }

    public String join(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }

        return scopes.stream()
                .filter(value -> value != null && !value.isBlank())
                .sorted()
                .collect(Collectors.joining(" "));
    }

    public boolean contains(Set<String> scopes, String requiredScope) {
        if (scopes == null || scopes.isEmpty()) {
            return false;
        }

        if (requiredScope == null || requiredScope.isBlank()) {
            return false;
        }

        return scopes.contains(requiredScope);
    }

    public boolean containsOpenId(Set<String> scopes) {
        return contains(scopes, "openid");
    }

    public boolean containsProfile(Set<String> scopes) {
        return contains(scopes, "profile");
    }

    public boolean containsEmail(Set<String> scopes) {
        return contains(scopes, "email");
    }

    public boolean containsOfflineAccess(Set<String> scopes) {
        return contains(scopes, "offline_access");
    }
}