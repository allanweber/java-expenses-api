package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.JwtResolveToken;
import com.allanweber.expenses.authentication.JwtTokenAuthenticationCheck;
import com.allanweber.expenses.authentication.JwtTokenReader;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class TokenAuthenticationCheck implements JwtTokenAuthenticationCheck {

    private final JwtTokenReader tokenReader;
    private final JwtResolveToken resolveToken;

    public TokenAuthenticationCheck(JwtTokenReader tokenReader, JwtResolveToken resolveToken) {
        this.tokenReader = tokenReader;
        this.resolveToken = resolveToken;
    }

    @Override
    public UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
        String token = resolveToken.resolve(request);
        if (StringUtils.hasText(token) && this.tokenReader.isTokenValid(token)) {
            usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) this.tokenReader.getAuthentication(token);
        }
        return usernamePasswordAuthenticationToken;
    }
}
