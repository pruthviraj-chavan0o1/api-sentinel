package com.pruthviraj.api_sentinel.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping("/test")
    public Map<String, String> secureTest(Authentication authentication) {

        Map<String, String> response = new HashMap<>();

        response.put("message", "You accessed a protected API");
        response.put("username", authentication.getName());
        response.put("status", "Authenticated");

        return response;
    }
}