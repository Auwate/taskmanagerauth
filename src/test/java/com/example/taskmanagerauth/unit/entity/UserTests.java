package com.example.taskmanagerauth.unit.entity;

import com.example.taskmanagerauth.entity.Role;
import com.example.taskmanagerauth.entity.User;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class UserTests {

    /**
     * Test basic behavior
     * ---
     * Test that the normal behavior of creation/getter/setter works
     */
    @Test
    void testBasicBehavior() {

        // Creation
        User testUser = new User();

        // Setters
        testUser.setId(1L);
        testUser.setPassword("Test password");
        testUser.setRoles(Set.of(Role.of("USER")));
        testUser.setUsername("Test username");
        testUser.setLastAccessedAt(LocalDateTime.of(2000, 12, 30, 12, 30, 45));

        // Getters
        assertEquals(1L, testUser.getId());
        assertEquals("Test password", testUser.getPassword());
        assertEquals("USER", testUser.getRoles().stream().findFirst().orElseThrow().getName());
        assertEquals("Test username", testUser.getUsername());
        assertEquals(LocalDateTime.of(2000, 12, 30, 12, 30, 45), testUser.getLastAccessedAt());

    }

}
