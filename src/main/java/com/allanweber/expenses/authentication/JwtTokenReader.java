package com.allanweber.expenses.authentication;

import org.springframework.security.core.Authentication;

public interface JwtTokenReader {
    Authentication getAuthentication(String token);

    AccessTokenInfo getAccessTokenInfo(String token);

    boolean isTokenValid(String token);
}
