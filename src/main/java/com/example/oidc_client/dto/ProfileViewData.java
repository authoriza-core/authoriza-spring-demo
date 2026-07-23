package com.example.oidc_client.dto;

public class ProfileViewData {

    private final UserData user = new UserData();
    private final RawTokenData rawTokens = new RawTokenData();
    private final ParsedTokenData parsedTokens = new ParsedTokenData();
    private final TokenValidationData validation = new TokenValidationData();

    public UserData getUser() {
        return user;
    }

    public RawTokenData getRawTokens() {
        return rawTokens;
    }

    public ParsedTokenData getParsedTokens() {
        return parsedTokens;
    }

    public TokenValidationData getValidation() {
        return validation;
    }

    public void updateValidation() {
        validation.setAccessTokenPresent(isPresent(rawTokens.getAccessToken()));
        validation.setRefreshTokenPresent(isPresent(rawTokens.getRefreshToken()));
        validation.setIdTokenPresent(isPresent(rawTokens.getIdToken()));

        validation.setSameJti(
                parsedTokens.getAccessTokenJti() != null
                        && parsedTokens.getIdTokenJti() != null
                        && parsedTokens.getAccessTokenJti()
                                .equals(parsedTokens.getIdTokenJti())
        );
    }

    private boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}