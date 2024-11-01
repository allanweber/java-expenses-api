package com.allanweber.expenses.authentication.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

class JwtExceptionTest {

    @DisplayName("Jwt exception with message")
    @Test
    void message() {
        JwtException exception = new JwtException("any message");
        assertThat(exception.getStatusText()).isEqualTo("any message");
        assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @DisplayName("Jwt exception with status")
    @Test
    void messageAndCause() {
        JwtException exception = new JwtException(HttpStatus.BAD_REQUEST, "any message");
        assertThat(exception.getStatusText()).isEqualTo("any message");
        assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}