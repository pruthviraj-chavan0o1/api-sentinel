package com.pruthviraj.api_sentinel.scanner;

import com.pruthviraj.api_sentinel.model.ScanResult;
import com.pruthviraj.api_sentinel.model.User;
import com.pruthviraj.api_sentinel.repository.ScanResultRepository;
import com.pruthviraj.api_sentinel.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scanner")
public class ScannerController {

    private final ApiScannerService apiScannerService;
    private final ScanResultRepository scanResultRepository;
    private final UserRepository userRepository;

    public ScannerController(
            ApiScannerService apiScannerService,
            ScanResultRepository scanResultRepository,
            UserRepository userRepository) {

        this.apiScannerService = apiScannerService;
        this.scanResultRepository = scanResultRepository;
        this.userRepository = userRepository;
    }

    @PostMapping("/scan")
    public ResponseEntity<?> scanApi(
            @RequestParam String url,
            Authentication authentication) {

        String username = authentication.getName();

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(401)
                    .body("Authenticated user not found.");
        }

        Map<String, Object> result =
                apiScannerService.scanApi(url, user);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public ResponseEntity<?> getScanHistory(
            Authentication authentication) {

        String username = authentication.getName();

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(401)
                    .body("Authenticated user not found.");
        }

        List<ScanResult> history =
                scanResultRepository
                        .findAllByUserOrderByScannedAtDesc(user);

        return ResponseEntity.ok(history);
    }

    @GetMapping("/history/{id}")
    public ResponseEntity<?> getScanById(
            @PathVariable Long id,
            Authentication authentication) {

        String username = authentication.getName();

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(401)
                    .body("Authenticated user not found.");
        }

        return scanResultRepository.findById(id)
                .filter(scan -> scan.getUser().getId()
                        .equals(user.getId()))
                .map(ResponseEntity::ok)
                .orElseGet(() ->
                        ResponseEntity.notFound().build()
                );
    }
}