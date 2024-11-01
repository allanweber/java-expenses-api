package com.allanweber.expenses.authentication;

import com.allanweber.expenses.authentication.token.TokenData;

import java.util.List;

public interface JwtTokenProvider {
    String TOKEN_TYPE = "JWT";
    String HEADER_TYP = "typ";
    String SCOPES = "scopes";
    String TENANCY_ID = "tenancy";
    String TENANCY_NAME = "org";
    String REFRESH_TOKEN = "REFRESH_TOKEN";

    TokenData generateAccessToken(ContextUser user, List<String> authorities);

    TokenData generateRefreshToken(ContextUser user);
}
