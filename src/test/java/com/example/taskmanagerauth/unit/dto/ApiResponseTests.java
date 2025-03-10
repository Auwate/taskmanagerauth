package com.example.taskmanagerauth.unit.dto;

import com.example.taskmanagerauth.dto.ApiResponse;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ApiResponseTests {

    @Test
    void testInitialization_Success() {

        ApiResponse<String> obj = new ApiResponse<>(
                200,
                "Test",
                "Test Data",
                LocalDateTime.of(1944, 10, 23, 12, 30, 15)
        );

        assertEquals(200, obj.getStatus());
        assertEquals("Test", obj.getMessage());
        assertEquals("Test Data", obj.getData());
        assertEquals("1944-10-23 12:30:15", obj.getTimestamp());

    }

    @Test
    void testStaticOfWithTimestamp_Success() {

        ApiResponse<List<Integer>> obj = ApiResponse.of(
                200,
                "Test",
                List.of(1,2,3),
                LocalDateTime.of(2000, 12, 7, 12, 45, 15)
        );

        assertEquals(200, obj.getStatus());
        assertEquals("Test", obj.getMessage());
        assertEquals(List.of(1,2,3), obj.getData());
        assertEquals("2000-12-07 12:45:15", obj.getTimestamp());

    }

}
