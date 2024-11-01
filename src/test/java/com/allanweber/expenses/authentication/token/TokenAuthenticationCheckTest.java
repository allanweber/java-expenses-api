package com.allanweber.expenses.authentication.token;

import com.allanweber.expenses.authentication.JwtTokenAuthenticationCheck;
import com.allanweber.expenses.authentication.JwtTokenReader;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static com.allanweber.expenses.authentication.token.JwtHttpHeaderAccessToken.TOKEN_PREFIX;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
class TokenAuthenticationCheckTest {

    @Mock
    JwtTokenReader tokenReader;

    JwtTokenAuthenticationCheck jwtTokenAuthenticationCheck;

    @BeforeEach
    public void setUp() {
        jwtTokenAuthenticationCheck = new TokenAuthenticationCheck(tokenReader, new JwtHttpHeaderAccessToken());
    }

    @Test
    @DisplayName("Given server request with token process request successfully")
    void serverRequestSuccess() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(TOKEN_PREFIX.concat("123456789"));

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer 123456789");
        when(tokenReader.isTokenValid("123456789")).thenReturn(true);
        when(tokenReader.getAuthentication("123456789")).thenReturn(new UsernamePasswordAuthenticationToken("user", null, emptyList()));

        UsernamePasswordAuthenticationToken authentication = jwtTokenAuthenticationCheck.getAuthentication(request);

        assertThat(authentication.getPrincipal()).isEqualTo("user");
    }

    @Test
    @DisplayName("Given server request without token process request successfully")
    void serverRequestSuccessWithoutToken() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        UsernamePasswordAuthenticationToken authentication = jwtTokenAuthenticationCheck.getAuthentication(request);

        assertThat(authentication).isNull();

        verify(tokenReader, never()).isTokenValid(anyString());
        verify(tokenReader, never()).getAuthentication(anyString());
    }
}