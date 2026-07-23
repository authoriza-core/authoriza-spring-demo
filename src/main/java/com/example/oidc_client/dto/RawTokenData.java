package com.example.oidc_client.dto;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public class RawTokenData {

    private String tokenType;

    private String accessToken;
    private String maskedAccessToken;

    private String refreshToken;
    private String maskedRefreshToken;

    private String idToken;
    private String maskedIdToken;

    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    private Long accessTokenExpiresIn;

    private Set<String> scopes = Collections.emptySet();

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getMaskedAccessToken() {
        return maskedAccessToken;
    }

    public void setMaskedAccessToken(String maskedAccessToken) {
        this.maskedAccessToken = maskedAccessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getMaskedRefreshToken() {
        return maskedRefreshToken;
    }

    public void setMaskedRefreshToken(String maskedRefreshToken) {
        this.maskedRefreshToken = maskedRefreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getMaskedIdToken() {
        return maskedIdToken;
    }

    public void setMaskedIdToken(String maskedIdToken) {
        this.maskedIdToken = maskedIdToken;
    }

    public Instant getAccessTokenIssuedAt() {
        return accessTokenIssuedAt;
    }

    public void setAccessTokenIssuedAt(Instant accessTokenIssuedAt) {
        this.accessTokenIssuedAt = accessTokenIssuedAt;
    }

    public Instant getAccessTokenExpiresAt() {
        return accessTokenExpiresAt;
    }

    public void setAccessTokenExpiresAt(Instant accessTokenExpiresAt) {
        this.accessTokenExpiresAt = accessTokenExpiresAt;
    }

    public Instant getRefreshTokenIssuedAt() {
        return refreshTokenIssuedAt;
    }

    public void setRefreshTokenIssuedAt(Instant refreshTokenIssuedAt) {
        this.refreshTokenIssuedAt = refreshTokenIssuedAt;
    }

    public Instant getRefreshTokenExpiresAt() {
        return refreshTokenExpiresAt;
    }

    public void setRefreshTokenExpiresAt(Instant refreshTokenExpiresAt) {
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
    }

    public Long getAccessTokenExpiresIn() {
        return accessTokenExpiresIn;
    }

    public void setAccessTokenExpiresIn(Long accessTokenExpiresIn) {
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes == null
                ? Collections.emptySet()
                : Set.copyOf(scopes);
    }
}