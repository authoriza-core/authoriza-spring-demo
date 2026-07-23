package com.example.oidc_client.dto;

import java.util.Collections;
import java.util.Map;

public class ParsedTokenData {

    private Map<String, Object> accessTokenPayload = Collections.emptyMap();
    private Map<String, Object> idTokenPayload = Collections.emptyMap();

    private String accessTokenJti;
    private String idTokenJti;

    public Map<String, Object> getAccessTokenPayload() {
        return accessTokenPayload;
    }

    public void setAccessTokenPayload(Map<String, Object> accessTokenPayload) {
        this.accessTokenPayload = accessTokenPayload == null
                ? Collections.emptyMap()
                : Map.copyOf(accessTokenPayload);
    }

    public Map<String, Object> getIdTokenPayload() {
        return idTokenPayload;
    }

    public void setIdTokenPayload(Map<String, Object> idTokenPayload) {
        this.idTokenPayload = idTokenPayload == null
                ? Collections.emptyMap()
                : Map.copyOf(idTokenPayload);
    }

    public String getAccessTokenJti() {
        return accessTokenJti;
    }

    public void setAccessTokenJti(String accessTokenJti) {
        this.accessTokenJti = accessTokenJti;
    }

    public String getIdTokenJti() {
        return idTokenJti;
    }

    public void setIdTokenJti(String idTokenJti) {
        this.idTokenJti = idTokenJti;
    }
}