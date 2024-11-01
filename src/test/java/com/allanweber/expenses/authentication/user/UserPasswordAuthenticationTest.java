package com.allanweber.expenses.authentication.user;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserPasswordAuthenticationTest {

    @DisplayName("authenticate")
    @Test
    void authenticate() {
        UserPasswordAuthentication userPasswordAuthentication = new UserPasswordAuthentication();
        assertNull(userPasswordAuthentication.authenticate(null));
    }
}