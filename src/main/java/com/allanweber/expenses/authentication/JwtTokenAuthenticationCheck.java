package com.allanweber.expenses.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public interface JwtTokenAuthenticationCheck {
    UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request);
}
