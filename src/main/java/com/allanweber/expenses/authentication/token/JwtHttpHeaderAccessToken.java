package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.JwtResolveToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JwtHttpHeaderAccessToken implements JwtResolveToken {
    public static final String TOKEN_PREFIX = "Bearer ";

    @Override
    public String resolve(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        String token = null;
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            token = bearerToken.replace(TOKEN_PREFIX, "");
        }
        return token;
    }
}
