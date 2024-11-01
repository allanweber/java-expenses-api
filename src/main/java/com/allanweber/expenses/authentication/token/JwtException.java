package com.allanweber.expenses.authentication.token;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import java.io.Serial;

public class JwtException extends HttpClientErrorException {
    @Serial
    private static final long serialVersionUID = -6161720324171559483L;

    public JwtException(String message) {
        this(HttpStatus.UNAUTHORIZED, message);
    }

    public JwtException(HttpStatus status, String message) {
        super(status, message);
    }
}