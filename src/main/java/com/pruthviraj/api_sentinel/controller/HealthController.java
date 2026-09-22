package com.pruthviraj.api_sentinel.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> healthCheck() {

        Map<String, String> response = new HashMap<>();

        response.put("status", "UP");
        response.put("message", "API Sentinel is running");

        return response;
    }
}