package com.allanweber.expenses.configuration.security;

import com.allanweber.expenses.authentication.JwtTokenAuthenticationCheck;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenAuthenticationCheck jwtTokenAuthenticationCheck;

    public JwtTokenAuthenticationFilter(JwtTokenAuthenticationCheck jwtTokenAuthenticationCheck) {
        super();
        this.jwtTokenAuthenticationCheck = jwtTokenAuthenticationCheck;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        UsernamePasswordAuthenticationToken authentication = jwtTokenAuthenticationCheck.getAuthentication(request);
        if (authentication == null) {
            filterChain.doFilter(request, response);
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
