package com.allanweber.expenses.authentication.token;

import java.time.LocalDateTime;

public record TokenData(
        String token,
        LocalDateTime issuedAt) {
}