package com.pruthviraj.api_sentinel.scanner;

import com.pruthviraj.api_sentinel.model.ScanResult;
import com.pruthviraj.api_sentinel.model.User;
import com.pruthviraj.api_sentinel.repository.ScanResultRepository;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ApiScannerService {

    private final HttpClient httpClient;
    private final ScanResultRepository scanResultRepository;

    public ApiScannerService(
            ScanResultRepository scanResultRepository) {

        this.scanResultRepository = scanResultRepository;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    // =========================================================
    // MAIN API SCANNER
    // =========================================================

    public Map<String, Object> scanApi(
            String url,
            User user) {

        Map<String, Object> result =
                new LinkedHashMap<>();

        try {

            // =================================================
            // 1. URL VALIDATION
            // =================================================

            if (url == null || url.trim().isEmpty()) {

                result.put(
                        "status",
                        "SCAN_FAILED"
                );

                result.put(
                        "error",
                        "API URL cannot be empty."
                );

                return result;
            }

            URI uri;

            try {

                uri = URI.create(url);

            } catch (IllegalArgumentException e) {

                result.put(
                        "url",
                        url
                );

                result.put(
                        "status",
                        "SCAN_FAILED"
                );

                result.put(
                        "error",
                        "Invalid URL."
                );

                return result;
            }

            String scheme =
                    uri.getScheme();

            if (scheme == null ||
                    (!scheme.equalsIgnoreCase("http")
                            && !scheme.equalsIgnoreCase("https"))) {

                result.put(
                        "url",
                        url
                );

                result.put(
                        "status",
                        "SCAN_FAILED"
                );

                result.put(
                        "error",
                        "Only HTTP and HTTPS URLs are supported."
                );

                return result;
            }

            // =================================================
            // 2. SEND INITIAL REQUEST
            // =================================================

            long startTime =
                    System.currentTimeMillis();

            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(uri)
                            .timeout(
                                    Duration.ofSeconds(15)
                            )
                            .header(
                                    "User-Agent",
                                    "API-Sentinel-Security-Scanner/1.0"
                            )
                            .GET()
                            .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            long endTime =
                    System.currentTimeMillis();

            long responseTime =
                    endTime - startTime;

            int statusCode =
                    response.statusCode();

            // =================================================
            // 3. RESPONSE INFORMATION
            // =================================================

            String contentType =
                    response.headers()
                            .firstValue("content-type")
                            .orElse("Not specified");

            String server =
                    response.headers()
                            .firstValue("server")
                            .orElse("Not disclosed");

            int responseSize =
                    response.body().length();

            result.put(
                    "url",
                    url
            );

            result.put(
                    "method",
                    "GET"
            );

            result.put(
                    "statusCode",
                    statusCode
            );

            result.put(
                    "responseTimeMs",
                    responseTime
            );

            result.put(
                    "contentType",
                    contentType
            );

            result.put(
                    "server",
                    server
            );

            result.put(
                    "responseSize",
                    responseSize
            );

            // =================================================
            // 4. SECURITY HEADER CHECKS
            // =================================================

            List<String> missingHeaders =
                    new ArrayList<>();

            List<String> presentHeaders =
                    new ArrayList<>();

            checkHeader(
                    response,
                    "X-Content-Type-Options",
                    presentHeaders,
                    missingHeaders
            );

            checkHeader(
                    response,
                    "X-Frame-Options",
                    presentHeaders,
                    missingHeaders
            );

            checkHeader(
                    response,
                    "Content-Security-Policy",
                    presentHeaders,
                    missingHeaders
            );

            checkHeader(
                    response,
                    "Strict-Transport-Security",
                    presentHeaders,
                    missingHeaders
            );

            checkHeader(
                    response,
                    "Referrer-Policy",
                    presentHeaders,
                    missingHeaders
            );

            result.put(
                    "securityHeadersPresent",
                    presentHeaders
            );

            result.put(
                    "securityHeadersMissing",
                    missingHeaders
            );

            // =================================================
            // 5. EXISTING VULNERABILITY ANALYSIS
            // =================================================

            List<Map<String, String>> vulnerabilities =
                    generateVulnerabilityFindings(
                            url,
                            statusCode,
                            server,
                            missingHeaders
                    );

            result.put(
                    "vulnerabilities",
                    vulnerabilities
            );

            result.put(
                    "vulnerabilityCount",
                    vulnerabilities.size()
            );

            // =================================================
            // 6. OWASP API SECURITY ANALYSIS
            // =================================================

            List<OwaspFinding> owaspFindings =
                    generateOwaspFindings(
                            url,
                            statusCode,
                            contentType,
                            server,
                            missingHeaders,
                            response
                    );

            result.put(
                    "owaspFindings",
                    owaspFindings
            );

            result.put(
                    "owaspFindingCount",
                    owaspFindings.size()
            );

            // =================================================
            // 7. SECURITY SCORE
            // =================================================

            int securityScore =
                    calculateSecurityScore(
                            url,
                            statusCode,
                            server,
                            missingHeaders
                    );

            String riskLevel =
                    calculateRiskLevel(
                            securityScore
                    );

            result.put(
                    "securityScore",
                    securityScore
            );

            result.put(
                    "riskLevel",
                    riskLevel
            );

            // =================================================
            // 8. SAVE SCAN
            // =================================================

            ScanResult scanResult =
                    new ScanResult();

            scanResult.setUser(user);

            scanResult.setUrl(url);

            scanResult.setMethod("GET");

            scanResult.setStatusCode(
                    statusCode
            );

            scanResult.setResponseTimeMs(
                    responseTime
            );

            scanResult.setContentType(
                    contentType
            );

            scanResult.setServer(
                    server
            );

            scanResult.setResponseSize(
                    responseSize
            );

            scanResult.setSecurityHeadersPresent(
                    String.join(
                            ", ",
                            presentHeaders
                    )
            );

            scanResult.setSecurityHeadersMissing(
                    String.join(
                            ", ",
                            missingHeaders
                    )
            );

            scanResult.setSecurityScore(
                    securityScore
            );

            scanResult.setRiskLevel(
                    riskLevel
            );

            scanResult.setScannedAt(
                    LocalDateTime.now()
            );

            ScanResult savedResult =
                    scanResultRepository.save(
                            scanResult
                    );

            result.put(
                    "scanId",
                    savedResult.getId()
            );

            result.put(
                    "status",
                    "SCAN_COMPLETED"
            );

        } catch (Exception e) {

            result.put(
                    "url",
                    url
            );

            result.put(
                    "status",
                    "SCAN_FAILED"
            );

            result.put(
                    "error",
                    e.getMessage()
            );
        }

        return result;
    }

    // =========================================================
    // SECURITY HEADER CHECK
    // =========================================================

    private void checkHeader(
            HttpResponse<String> response,
            String headerName,
            List<String> presentHeaders,
            List<String> missingHeaders) {

        if (response.headers()
                .firstValue(headerName)
                .isPresent()) {

            presentHeaders.add(
                    headerName
            );

        } else {

            missingHeaders.add(
                    headerName
            );
        }
    }

    // =========================================================
    // OWASP API SECURITY CHECKS
    // =========================================================

    private List<OwaspFinding> generateOwaspFindings(
            String url,
            int statusCode,
            String contentType,
            String server,
            List<String> missingHeaders,
            HttpResponse<String> response) {

        List<OwaspFinding> findings =
                new ArrayList<>();

        // =====================================================
        // API1:2023
        // BROKEN OBJECT LEVEL AUTHORIZATION
        // =====================================================

        findings.add(
                new OwaspFinding(
                        "API1:2023",
                        "Broken Object Level Authorization",
                        "INFO",
                        "NOT_TESTABLE",
                        "A single endpoint request cannot conclusively verify object-level authorization. Object identifiers and authorization boundaries require endpoint-specific testing.",
                        "Test object access using different authorized test accounts and verify that one user cannot access another user's objects."
                )
        );

        // =====================================================
        // API2:2023
        // BROKEN AUTHENTICATION
        // =====================================================

        performAuthenticationCheck(
                url,
                findings
        );

        // =====================================================
        // API3:2023
        // BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION
        // =====================================================

        String body =
                response.body();

        boolean possibleSensitiveData =
                containsSensitiveField(body);

        if (possibleSensitiveData) {

            findings.add(
                    new OwaspFinding(
                            "API3:2023",
                            "Potential Sensitive Property Exposure",
                            "MEDIUM",
                            "POTENTIAL",
                            "The response contains field names that may represent sensitive properties.",
                            "Review response schemas and ensure users receive only properties they are authorized to access."
                    )
            );

        } else {

            findings.add(
                    new OwaspFinding(
                            "API3:2023",
                            "Object Property Authorization",
                            "INFO",
                            "NOT_DETECTED",
                            "No obvious sensitive property names were detected in the response body.",
                            "Perform schema-based testing to verify that sensitive properties are not exposed."
                    )
            );
        }

        // =====================================================
        // API4:2023
        // UNRESTRICTED RESOURCE CONSUMPTION
        // =====================================================

        performRateLimitCheck(
                url,
                response,
                findings
        );

        // =====================================================
        // API5:2023
        // BROKEN FUNCTION LEVEL AUTHORIZATION
        // =====================================================

        findings.add(
                new OwaspFinding(
                        "API5:2023",
                        "Function Level Authorization",
                        "INFO",
                        "NOT_TESTABLE",
                        "A normal endpoint request cannot determine whether administrative or privileged functions are correctly protected.",
                        "Test privileged endpoints with accounts having different roles and verify that unauthorized users receive an appropriate denial."
                )
        );

        // =====================================================
        // API6:2023
        // UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS
        // =====================================================

        findings.add(
                new OwaspFinding(
                        "API6:2023",
                        "Sensitive Business Flow Protection",
                        "INFO",
                        "NOT_TESTABLE",
                        "Business-flow abuse cannot be determined from a single endpoint response.",
                        "Identify sensitive workflows such as registration, password reset, payments or account changes and apply appropriate abuse protections."
                )
        );

        // =====================================================
        // API7:2023
        // SERVER SIDE REQUEST FORGERY
        // =====================================================

        performSsrfIndicatorCheck(
                url,
                findings
        );

        // =====================================================
        // API8:2023
        // SECURITY MISCONFIGURATION
        // =====================================================

        performSecurityConfigurationCheck(
                url,
                statusCode,
                contentType,
                server,
                missingHeaders,
                response,
                findings
        );

        // =====================================================
        // API9:2023
        // IMPROPER INVENTORY MANAGEMENT
        // =====================================================

        performInventoryCheck(
                url,
                findings
        );

        // =====================================================
        // API10:2023
        // UNSAFE CONSUMPTION OF APIS
        // =====================================================

        performApiConsumptionCheck(
                response,
                findings
        );

        return findings;
    }

    // =========================================================
    // API2 AUTHENTICATION CHECK
    // =========================================================

    private void performAuthenticationCheck(
            String url,
            List<OwaspFinding> findings) {

        try {

            // -------------------------------------------------
            // Request 1: no authentication
            // -------------------------------------------------

            HttpRequest unauthenticatedRequest =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(
                                    Duration.ofSeconds(10)
                            )
                            .header(
                                    "User-Agent",
                                    "API-Sentinel-Security-Scanner/1.0"
                            )
                            .GET()
                            .build();

            HttpResponse<String> unauthenticatedResponse =
                    httpClient.send(
                            unauthenticatedRequest,
                            HttpResponse.BodyHandlers.ofString()
                    );

            int unauthenticatedStatus =
                    unauthenticatedResponse.statusCode();

            // -------------------------------------------------
            // Request 2: intentionally invalid token
            // -------------------------------------------------

            HttpRequest invalidTokenRequest =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(
                                    Duration.ofSeconds(10)
                            )
                            .header(
                                    "User-Agent",
                                    "API-Sentinel-Security-Scanner/1.0"
                            )
                            .header(
                                    "Authorization",
                                    "Bearer invalid-api-sentinel-token"
                            )
                            .GET()
                            .build();

            HttpResponse<String> invalidTokenResponse =
                    httpClient.send(
                            invalidTokenRequest,
                            HttpResponse.BodyHandlers.ofString()
                    );

            int invalidTokenStatus =
                    invalidTokenResponse.statusCode();

            // -------------------------------------------------
            // Analyze authentication behavior
            // -------------------------------------------------

            if (unauthenticatedStatus == 401 &&
                    invalidTokenStatus == 401) {

                findings.add(
                        new OwaspFinding(
                                "API2:2023",
                                "Authentication Enforcement Observed",
                                "INFO",
                                "NOT_DETECTED",
                                "The endpoint rejected both the unauthenticated request and the intentionally invalid bearer token with HTTP 401.",
                                "Continue testing valid, expired and revoked credentials."
                        )
                );

            } else if (
                    unauthenticatedStatus == 401 &&
                            invalidTokenStatus != 401) {

                findings.add(
                        new OwaspFinding(
                                "API2:2023",
                                "Inconsistent Authentication Response",
                                "MEDIUM",
                                "POTENTIAL",
                                "The endpoint rejected the request without credentials but returned a different response for an invalid bearer token.",
                                "Review authentication middleware and ensure invalid credentials are consistently rejected."
                        )
                );

            } else if (
                    unauthenticatedStatus >= 200 &&
                            unauthenticatedStatus < 300) {

                findings.add(
                        new OwaspFinding(
                                "API2:2023",
                                "Authentication Not Required or Not Enforced",
                                "MEDIUM",
                                "POTENTIAL",
                                "The endpoint returned a successful response without authentication. This may be intentional for public APIs and therefore requires endpoint-specific review.",
                                "Confirm whether this endpoint is intentionally public. If authentication is required, enforce it consistently."
                        )
                );

            } else {

                findings.add(
                        new OwaspFinding(
                                "API2:2023",
                                "Authentication Behavior Requires Review",
                                "LOW",
                                "POTENTIAL",
                                "The scanner observed authentication-related responses that require endpoint-specific review.",
                                "Test valid, invalid, expired and revoked credentials and verify the expected authorization behavior."
                        )
                );
            }

        } catch (Exception e) {

            findings.add(
                    new OwaspFinding(
                            "API2:2023",
                            "Authentication Test Failed",
                            "INFO",
                            "NOT_TESTABLE",
                            "The scanner could not complete the controlled authentication checks.",
                            "Perform authorized authentication testing manually or with valid test credentials."
                    )
            );
        }
    }

    // =========================================================
    // API4 RATE LIMIT CHECK
    // =========================================================

    private void performRateLimitCheck(
            String url,
            HttpResponse<String> originalResponse,
            List<OwaspFinding> findings) {

        String retryAfter =
                originalResponse.headers()
                        .firstValue("Retry-After")
                        .orElse(null);

        if (retryAfter != null) {

            findings.add(
                    new OwaspFinding(
                            "API4:2023",
                            "Rate Limiting Indicator",
                            "INFO",
                            "DETECTED",
                            "The response includes a Retry-After header, which can indicate throttling or rate limiting.",
                            "Verify rate limits under controlled authorized testing and ensure resource-intensive operations have appropriate limits."
                    )
            );

            return;
        }

        try {

            int totalRequests = 5;

            int rateLimitedResponses = 0;

            int successfulResponses = 0;

            long totalResponseTime = 0;

            for (int i = 0; i < totalRequests; i++) {

                long start =
                        System.currentTimeMillis();

                HttpRequest request =
                        HttpRequest.newBuilder()
                                .uri(URI.create(url))
                                .timeout(
                                        Duration.ofSeconds(10)
                                )
                                .header(
                                        "User-Agent",
                                        "API-Sentinel-Security-Scanner/1.0"
                                )
                                .GET()
                                .build();

                HttpResponse<String> response =
                        httpClient.send(
                                request,
                                HttpResponse.BodyHandlers.ofString()
                        );

                long end =
                        System.currentTimeMillis();

                totalResponseTime +=
                        end - start;

                int currentStatus =
                        response.statusCode();

                if (currentStatus == 429) {

                    rateLimitedResponses++;

                } else if (
                        currentStatus >= 200 &&
                                currentStatus < 300) {

                    successfulResponses++;
                }
            }

            long averageResponseTime =
                    totalResponseTime / totalRequests;

            if (rateLimitedResponses > 0) {

                findings.add(
                        new OwaspFinding(
                                "API4:2023",
                                "Rate Limiting Detected",
                                "INFO",
                                "DETECTED",
                                "The controlled request burst received HTTP 429 responses, indicating that the endpoint applies rate limiting or throttling.",
                                "Review the rate-limit policy and ensure limits are appropriate for the endpoint and authenticated users."
                        )
                );

            } else if (
                    successfulResponses == totalRequests) {

                findings.add(
                        new OwaspFinding(
                                "API4:2023",
                                "Rate Limiting Requires Review",
                                "LOW",
                                "POTENTIAL",
                                "Five controlled requests completed without an HTTP 429 response. This does not prove that rate limiting is absent.",
                                "Perform larger authorized load testing where appropriate and verify rate limits for authenticated and unauthenticated clients."
                        )
                );

            } else {

                findings.add(
                        new OwaspFinding(
                                "API4:2023",
                                "Resource Consumption Requires Review",
                                "INFO",
                                "NOT_TESTABLE",
                                "The controlled request sequence produced mixed responses and could not conclusively determine the rate-limit policy.",
                                "Review endpoint-specific throttling and resource consumption controls."
                        )
                );
            }

        } catch (Exception e) {

            findings.add(
                    new OwaspFinding(
                            "API4:2023",
                            "Rate Limit Test Failed",
                            "INFO",
                            "NOT_TESTABLE",
                            "The scanner could not complete the controlled rate-limit test.",
                            "Perform authorized rate-limit testing using an appropriate test environment."
                    )
            );
        }
    }

    // =========================================================
    // API7 SSRF INDICATOR CHECK
    // =========================================================

    private void performSsrfIndicatorCheck(
            String url,
            List<OwaspFinding> findings) {

        try {

            URI uri =
                    URI.create(url);

            String host =
                    uri.getHost();

            if (host == null) {

                findings.add(
                        new OwaspFinding(
                                "API7:2023",
                                "SSRF",
                                "INFO",
                                "NOT_TESTABLE",
                                "The scanner could not determine the target host from the supplied URL.",
                                "Review endpoints that accept user-controlled URLs or remote resources."
                        )
                );

                return;
            }

            String lowerHost =
                    host.toLowerCase();

            if (
                    lowerHost.equals("localhost")
                            || lowerHost.equals("127.0.0.1")
                            || lowerHost.equals("0.0.0.0")
                            || lowerHost.equals("::1")
            ) {

                findings.add(
                        new OwaspFinding(
                                "API7:2023",
                                "Local/Internal Target Indicator",
                                "INFO",
                                "DETECTED",
                                "The scanned endpoint uses a local or loopback host. This does not prove an SSRF vulnerability.",
                                "If the application accepts user-controlled URLs, restrict access to internal networks, loopback addresses and cloud metadata services."
                        )
                );

            } else {

                findings.add(
                        new OwaspFinding(
                                "API7:2023",
                                "SSRF",
                                "INFO",
                                "NOT_TESTABLE",
                                "A normal request to the target endpoint cannot confirm whether the application is vulnerable to server-side request forgery.",
                                "Review URL-fetching functionality and enforce strict destination allowlists."
                        )
                );
            }

        } catch (Exception e) {

            findings.add(
                    new OwaspFinding(
                            "API7:2023",
                            "SSRF Analysis Failed",
                            "INFO",
                            "NOT_TESTABLE",
                            "The scanner could not analyze the target URL for SSRF indicators.",
                            "Review endpoints that accept URLs or remote resources."
                    )
            );
        }
    }

    // =========================================================
    // API8 SECURITY CONFIGURATION CHECK
    // =========================================================

    private void performSecurityConfigurationCheck(
            String url,
            int statusCode,
            String contentType,
            String server,
            List<String> missingHeaders,
            HttpResponse<String> response,
            List<OwaspFinding> findings) {

        List<String> configurationIssues =
                new ArrayList<>();

        if (!url.toLowerCase()
                .startsWith("https://")) {

            configurationIssues.add(
                    "Endpoint is using HTTP"
            );
        }

        if (!missingHeaders.isEmpty()) {

            configurationIssues.add(
                    "Security headers are missing"
            );
        }

        if (statusCode >= 500) {

            configurationIssues.add(
                    "Server returned an HTTP 5xx response"
            );
        }

        String body =
                response.body();

        if (body != null) {

            String lowerBody =
                    body.toLowerCase();

            if (
                    lowerBody.contains("stacktrace")
                            || lowerBody.contains("exception")
                            || lowerBody.contains("whitelabel error page")
            ) {

                configurationIssues.add(
                        "Potential error information disclosure"
                );
            }
        }

        if (!"Not disclosed"
                .equalsIgnoreCase(server)) {

            configurationIssues.add(
                    "Server header is exposed"
            );
        }

        if (!configurationIssues.isEmpty()) {

            findings.add(
                    new OwaspFinding(
                            "API8:2023",
                            "Security Misconfiguration",
                            "MEDIUM",
                            "POTENTIAL",
                            "The scanner identified configuration indicators requiring review: "
                                    + String.join(
                                    ", ",
                                    configurationIssues
                            ),
                            "Review TLS, security headers, error handling, server configuration and production security settings."
                    )
            );

        } else {

            findings.add(
                    new OwaspFinding(
                            "API8:2023",
                            "Security Configuration",
                            "INFO",
                            "NOT_DETECTED",
                            "No major security configuration indicators were identified by the checks performed.",
                            "Continue reviewing TLS, CORS, framework configuration and error handling."
                    )
            );
        }
    }

    // =========================================================
    // API9 API INVENTORY CHECK
    // =========================================================

    private void performInventoryCheck(
            String url,
            List<OwaspFinding> findings) {

        try {

            URI uri =
                    URI.create(url);

            String path =
                    uri.getPath();

            if (path == null ||
                    path.trim().isEmpty()) {

                findings.add(
                        new OwaspFinding(
                                "API9:2023",
                                "API Inventory",
                                "INFO",
                                "NOT_TESTABLE",
                                "The scanner cannot determine whether all API endpoints and versions are properly inventoried.",
                                "Maintain an inventory of production, development, deprecated and undocumented API endpoints."
                        )
                );

                return;
            }

            String lowerPath =
                    path.toLowerCase();

            boolean looksLikeVersionedApi =
                    lowerPath.matches(
                            ".*\\/v[0-9]+(\\/.*)?"
                    );

            if (looksLikeVersionedApi) {

                findings.add(
                        new OwaspFinding(
                                "API9:2023",
                                "Versioned API Endpoint Detected",
                                "LOW",
                                "POTENTIAL",
                                "The endpoint path appears to contain an API version identifier.",
                                "Track API versions in an inventory and securely retire deprecated versions."
                        )
                );

            } else {

                findings.add(
                        new OwaspFinding(
                                "API9:2023",
                                "API Inventory",
                                "INFO",
                                "NOT_TESTABLE",
                                "A single endpoint cannot establish whether the complete API inventory is maintained.",
                                "Maintain an inventory of API endpoints, versions, environments and deprecated services."
                        )
                );
            }

        } catch (Exception e) {

            findings.add(
                    new OwaspFinding(
                            "API9:2023",
                            "API Inventory Check Failed",
                            "INFO",
                            "NOT_TESTABLE",
                            "The scanner could not analyze the endpoint path.",
                            "Review API versioning and inventory management manually."
                    )
            );
        }
    }

    // =========================================================
    // API10 UNSAFE API CONSUMPTION CHECK
    // =========================================================

    private void performApiConsumptionCheck(
            HttpResponse<String> response,
            List<OwaspFinding> findings) {

        String accessControlAllowOrigin =
                response.headers()
                        .firstValue(
                                "Access-Control-Allow-Origin"
                        )
                        .orElse(null);

        String contentType =
                response.headers()
                        .firstValue("content-type")
                        .orElse("");

        if (
                accessControlAllowOrigin != null
                        && accessControlAllowOrigin.equals("*")
        ) {

            findings.add(
                    new OwaspFinding(
                            "API10:2023",
                            "Permissive CORS Policy",
                            "LOW",
                            "POTENTIAL",
                            "The endpoint allows cross-origin access using a wildcard CORS policy.",
                            "Verify that cross-origin access is intentional and restrict trusted origins where sensitive data is involved."
                    )
            );

        } else {

            findings.add(
                    new OwaspFinding(
                            "API10:2023",
                            "Unsafe API Consumption",
                            "INFO",
                            "NOT_TESTABLE",
                            "Safe consumption of external APIs cannot be determined from a single response.",
                            "Validate external API responses, use trusted providers and enforce clear trust boundaries for third-party data."
                    )
            );
        }
    }

    // =========================================================
    // SENSITIVE FIELD DETECTION
    // =========================================================

    private boolean containsSensitiveField(
            String body) {

        if (body == null ||
                body.trim().isEmpty()) {

            return false;
        }

        String lowerBody =
                body.toLowerCase();

        String[] sensitiveFields = {

                "password",
                "passwd",
                "secret",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "credit_card",
                "card_number",
                "cvv",
                "ssn"
        };

        for (String field :
                sensitiveFields) {

            if (lowerBody.contains(field)) {

                return true;
            }
        }

        return false;
    }

    // =========================================================
    // EXISTING VULNERABILITY FINDINGS
    // =========================================================

    private List<Map<String, String>>
    generateVulnerabilityFindings(
            String url,
            int statusCode,
            String server,
            List<String> missingHeaders) {

        List<Map<String, String>>
                vulnerabilities =
                new ArrayList<>();

        // -----------------------------------------------------
        // HTTPS
        // -----------------------------------------------------

        if (!url.toLowerCase()
                .startsWith("https://")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "API is not using HTTPS"
            );

            finding.put(
                    "severity",
                    "HIGH"
            );

            finding.put(
                    "description",
                    "The API endpoint is using HTTP instead of HTTPS."
            );

            finding.put(
                    "recommendation",
                    "Use HTTPS to protect data transmitted between clients and the API."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // CSP
        // -----------------------------------------------------

        if (missingHeaders.contains(
                "Content-Security-Policy")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Missing Content-Security-Policy header"
            );

            finding.put(
                    "severity",
                    "MEDIUM"
            );

            finding.put(
                    "description",
                    "The response does not define a Content-Security-Policy header."
            );

            finding.put(
                    "recommendation",
                    "Configure an appropriate Content-Security-Policy for the application."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // HSTS
        // -----------------------------------------------------

        if (missingHeaders.contains(
                "Strict-Transport-Security")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Missing Strict-Transport-Security header"
            );

            finding.put(
                    "severity",
                    "MEDIUM"
            );

            finding.put(
                    "description",
                    "The response does not include the HSTS security header."
            );

            finding.put(
                    "recommendation",
                    "Configure Strict-Transport-Security when the application is served over HTTPS."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // REFERRER POLICY
        // -----------------------------------------------------

        if (missingHeaders.contains(
                "Referrer-Policy")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Missing Referrer-Policy header"
            );

            finding.put(
                    "severity",
                    "LOW"
            );

            finding.put(
                    "description",
                    "The response does not define a Referrer-Policy."
            );

            finding.put(
                    "recommendation",
                    "Configure a suitable Referrer-Policy to control referrer information."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // X-CONTENT-TYPE-OPTIONS
        // -----------------------------------------------------

        if (missingHeaders.contains(
                "X-Content-Type-Options")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Missing X-Content-Type-Options header"
            );

            finding.put(
                    "severity",
                    "MEDIUM"
            );

            finding.put(
                    "description",
                    "The response does not prevent MIME type sniffing."
            );

            finding.put(
                    "recommendation",
                    "Configure X-Content-Type-Options with the value nosniff."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // X-FRAME-OPTIONS
        // -----------------------------------------------------

        if (missingHeaders.contains(
                "X-Frame-Options")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Missing X-Frame-Options header"
            );

            finding.put(
                    "severity",
                    "LOW"
            );

            finding.put(
                    "description",
                    "The response does not specify whether it can be embedded in frames."
            );

            finding.put(
                    "recommendation",
                    "Configure X-Frame-Options or an equivalent CSP frame-ancestors policy where appropriate."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // SERVER DISCLOSURE
        // -----------------------------------------------------

        if (!server.equalsIgnoreCase(
                "Not disclosed")) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Server information disclosed"
            );

            finding.put(
                    "severity",
                    "LOW"
            );

            finding.put(
                    "description",
                    "The response exposes a Server header."
            );

            finding.put(
                    "recommendation",
                    "Consider minimizing unnecessary server information exposed in HTTP response headers."
            );

            vulnerabilities.add(
                    finding
            );
        }

        // -----------------------------------------------------
        // SERVER ERROR
        // -----------------------------------------------------

        if (statusCode >= 500) {

            Map<String, String> finding =
                    new LinkedHashMap<>();

            finding.put(
                    "title",
                    "Server returned an error"
            );

            finding.put(
                    "severity",
                    "HIGH"
            );

            finding.put(
                    "description",
                    "The API returned an HTTP 5xx server error."
            );

            finding.put(
                    "recommendation",
                    "Review server logs and application error handling."
            );

            vulnerabilities.add(
                    finding
            );
        }

        return vulnerabilities;
    }

    // =========================================================
    // SECURITY SCORE
    // =========================================================

    private int calculateSecurityScore(
            String url,
            int statusCode,
            String server,
            List<String> missingHeaders) {

        int score = 100;

        if (!url.toLowerCase()
                .startsWith("https://")) {

            score -= 20;
        }

        score -=
                missingHeaders.size() * 10;

        if (!server.equalsIgnoreCase(
                "Not disclosed")) {

            score -= 5;
        }

        if (statusCode >= 500) {

            score -= 20;
        }

        return Math.max(
                score,
                0
        );
    }

    // =========================================================
    // RISK LEVEL
    // =========================================================

    private String calculateRiskLevel(
            int score) {

        if (score >= 80) {

            return "LOW";
        }

        if (score >= 50) {

            return "MEDIUM";
        }

        return "HIGH";
    }
}