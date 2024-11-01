package com.allanweber.expenses.authentication;

public record ContextUser(String email, Long tenancyId, String tenancyName) {
}
