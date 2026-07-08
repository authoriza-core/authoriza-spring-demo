package com.example.oidc_client.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@Component
public class JwtPayloadDecoder {

    private final ObjectMapper objectMapper;

    public JwtPayloadDecoder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> decodePayload(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return Collections.emptyMap();
        }

        String[] parts = jwt.split("\\.");

        if (parts.length < 2) {
            return Collections.emptyMap();
        }

        try {
            byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);
            String jsonPayload = new String(decodedBytes, StandardCharsets.UTF_8);

            return objectMapper.readValue(
                    jsonPayload,
                    new TypeReference<Map<String, Object>>() {
                    }
            );
        } catch (Exception exception) {
            return Collections.emptyMap();
        }
    }

    public String extractStringClaim(String jwt, String claimName) {
        if (claimName == null || claimName.isBlank()) {
            return null;
        }

        Map<String, Object> payload = decodePayload(jwt);
        Object value = payload.get(claimName);

        if (value == null) {
            return null;
        }

        return String.valueOf(value);
    }

    public String extractJti(String jwt) {
        return extractStringClaim(jwt, "jti");
    }

    public String extractSubject(String jwt) {
        return extractStringClaim(jwt, "sub");
    }

    public String extractEmail(String jwt) {
        return extractStringClaim(jwt, "email");
    }
}