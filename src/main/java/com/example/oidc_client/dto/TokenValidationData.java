package com.example.oidc_client.dto;

import java.time.Instant;

public class TokenValidationData {

    private boolean accessTokenPresent;
    private boolean refreshTokenPresent;
    private boolean idTokenPresent;
    private boolean sameJti;

    private Instant lastUpdatedAt;

    public boolean isAccessTokenPresent() {
        return accessTokenPresent;
    }

    public void setAccessTokenPresent(boolean accessTokenPresent) {
        this.accessTokenPresent = accessTokenPresent;
    }

    public boolean isRefreshTokenPresent() {
        return refreshTokenPresent;
    }

    public void setRefreshTokenPresent(boolean refreshTokenPresent) {
        this.refreshTokenPresent = refreshTokenPresent;
    }

    public boolean isIdTokenPresent() {
        return idTokenPresent;
    }

    public void setIdTokenPresent(boolean idTokenPresent) {
        this.idTokenPresent = idTokenPresent;
    }

    public boolean isSameJti() {
        return sameJti;
    }

    public void setSameJti(boolean sameJti) {
        this.sameJti = sameJti;
    }

    public Instant getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    public void setLastUpdatedAt(Instant lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }
}