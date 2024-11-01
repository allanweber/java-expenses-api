package com.allanweber.expenses.authentication.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("application.authentication.jwt")
public record JwtProperties(
        String privateKey,
        Long accessTokenExpiration,
        Long refreshTokenExpiration,

        String issuer,

        String audience
) {

}
