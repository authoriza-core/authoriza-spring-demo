package com.example.oidc_client.dto;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class ProfileViewData {

    private String principalName;
    private String displayName;
    private String email;
    private String subject;

    private String clientRegistrationId;
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

    private Set<String> scopes = Collections.emptySet();

    private Map<String, Object> accessTokenPayload = Collections.emptyMap();
    private Map<String, Object> idTokenPayload = Collections.emptyMap();

    private String accessTokenJti;
    private String idTokenJti;
    private boolean sameJti;

    private boolean accessTokenPresent;
    private boolean refreshTokenPresent;
    private boolean idTokenPresent;

    private Instant lastUpdatedAt;
    private Long accessTokenExpiresIn;

    public Long getAccessTokenExpiresIn() {
        return accessTokenExpiresIn;
    }

    public void setAccessTokenExpiresIn(Long accessTokenExpiresIn) {
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getClientRegistrationId() {
        return clientRegistrationId;
    }

    public void setClientRegistrationId(String clientRegistrationId) {
        this.clientRegistrationId = clientRegistrationId;
    }

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
        this.accessTokenPresent = accessToken != null && !accessToken.isBlank();
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
        this.refreshTokenPresent = refreshToken != null && !refreshToken.isBlank();
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
        this.idTokenPresent = idToken != null && !idToken.isBlank();
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

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
    }

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
        updateSameJti();
    }

    public String getIdTokenJti() {
        return idTokenJti;
    }

    public void setIdTokenJti(String idTokenJti) {
        this.idTokenJti = idTokenJti;
        updateSameJti();
    }

    public boolean isSameJti() {
        return sameJti;
    }

    public boolean isAccessTokenPresent() {
        return accessTokenPresent;
    }

    public boolean isRefreshTokenPresent() {
        return refreshTokenPresent;
    }

    public boolean isIdTokenPresent() {
        return idTokenPresent;
    }

    public Instant getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    public void setLastUpdatedAt(Instant lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }

    private void updateSameJti() {
        this.sameJti = accessTokenJti != null
                && idTokenJti != null
                && accessTokenJti.equals(idTokenJti);
    }
}