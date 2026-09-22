package com.pruthviraj.api_sentinel.controller;

import com.pruthviraj.api_sentinel.model.User;
import com.pruthviraj.api_sentinel.repository.UserRepository;
import com.pruthviraj.api_sentinel.service.JwtService;
import com.pruthviraj.api_sentinel.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    private final BCryptPasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();

    public AuthController(
            UserService userService,
            UserRepository userRepository,
            JwtService jwtService) {

        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {

        try {

            User registeredUser = userService.registerUser(user);

            registeredUser.setPassword(null);

            return ResponseEntity.ok(registeredUser);

        } catch (RuntimeException e) {

            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {

        User user = userRepository
                .findByUsername(loginRequest.getUsername())
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(401)
                    .body("Invalid username or password");
        }

        boolean passwordMatches = passwordEncoder.matches(
                loginRequest.getPassword(),
                user.getPassword()
        );

        if (!passwordMatches) {
            return ResponseEntity
                    .status(401)
                    .body("Invalid username or password");
        }

        String token = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );

        Map<String, Object> response = new HashMap<>();

        response.put("message", "Login successful");
        response.put("username", user.getUsername());
        response.put("role", user.getRole());
        response.put("token", token);

        return ResponseEntity.ok(response);
    }
}