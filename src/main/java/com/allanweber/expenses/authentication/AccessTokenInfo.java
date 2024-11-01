package com.allanweber.expenses.authentication;

import java.util.List;

public record AccessTokenInfo(
        String subject,
        Long tenancyId,
        String tenancyName,
        List<String> scopes) {
}

