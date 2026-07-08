package com.example.oidc_client.util;

import org.springframework.stereotype.Component;

@Component
public class TokenMasker {

    private static final int DEFAULT_VISIBLE_PREFIX_LENGTH = 12;
    private static final int DEFAULT_VISIBLE_SUFFIX_LENGTH = 8;

    public String mask(String token) {
        return mask(token, DEFAULT_VISIBLE_PREFIX_LENGTH, DEFAULT_VISIBLE_SUFFIX_LENGTH);
    }

    public String mask(String token, int visiblePrefixLength, int visibleSuffixLength) {
        if (token == null || token.isBlank()) {
            return "—";
        }

        if (visiblePrefixLength < 0) {
            visiblePrefixLength = 0;
        }

        if (visibleSuffixLength < 0) {
            visibleSuffixLength = 0;
        }

        int visibleCharactersCount = visiblePrefixLength + visibleSuffixLength;

        if (token.length() <= visibleCharactersCount) {
            return token;
        }

        String prefix = token.substring(0, visiblePrefixLength);
        String suffix = token.substring(token.length() - visibleSuffixLength);

        return prefix + "..." + suffix;
    }

    public String maskShort(String token) {
        return mask(token, 6, 4);
    }

    public String maskLong(String token) {
        return mask(token, 20, 12);
    }

    public boolean isPresent(String token) {
        return token != null && !token.isBlank();
    }
}