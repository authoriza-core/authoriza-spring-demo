package com.example.oidc_client.storage;

import java.time.Instant;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;

@Entity
public class StoredAuthData {

    @Id
    private String registrationId;

    private String principalName;

    @Lob
    private String accessToken;

    @Lob
    private String refreshToken;

    @Lob
    private String idToken;

    private Instant accessTokenIssuedAt;

    private Instant accessTokenExpiresAt;

    private Instant refreshTokenIssuedAt;

    private Instant idTokenIssuedAt;

    private Instant idTokenExpiresAt;

    private String scopes;

    private Instant lastUpdatedAt;


    public Instant getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    public void setLastUpdatedAt(Instant lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }
    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
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

    public Instant getIdTokenIssuedAt() {
        return idTokenIssuedAt;
    }

    public void setIdTokenIssuedAt(Instant idTokenIssuedAt) {
        this.idTokenIssuedAt = idTokenIssuedAt;
    }

    public Instant getIdTokenExpiresAt() {
        return idTokenExpiresAt;
    }

    public void setIdTokenExpiresAt(Instant idTokenExpiresAt) {
        this.idTokenExpiresAt = idTokenExpiresAt;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }
}