package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.JwtResolveToken;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.UUID;

import static com.allanweber.expenses.authentication.token.JwtHttpHeaderAccessToken.TOKEN_PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
class JwtHttpHeaderAccessTokenTest {

    JwtResolveToken jwtResolveToken;

    @BeforeEach
    public void setUp() {
        jwtResolveToken = new JwtHttpHeaderAccessToken();
    }

    @Test
    @DisplayName("Given server request with token return token value")
    void requestWithToken() {
        String token = UUID.randomUUID().toString();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(TOKEN_PREFIX.concat(token));
        String resolved = jwtResolveToken.resolve(request);
        assertThat(resolved).isEqualTo(token);
    }

    @Test
    @DisplayName("Given server request without token return null")
    void requestWithoutToken() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String resolved = jwtResolveToken.resolve(request);
        assertThat(resolved).isNull();
    }

    @Test
    @DisplayName("Given server request without token because header values does not have the prefix return null")
    void requestWithoutToken2() {
        String token = UUID.randomUUID().toString();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(token);
        String resolved = jwtResolveToken.resolve(request);
        assertThat(resolved).isNull();
    }

    @Test
    @DisplayName("Given server request without because value is empty token return token value")
    void requestWithToken3() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("");
        String resolved = jwtResolveToken.resolve(request);
        assertThat(resolved).isNull();
    }
}