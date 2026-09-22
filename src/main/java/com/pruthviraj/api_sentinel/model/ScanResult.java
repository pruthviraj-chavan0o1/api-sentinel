package com.pruthviraj.api_sentinel.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String url;

    @Column(nullable = false)
    private String method;

    @Column(nullable = false)
    private int statusCode;

    @Column(nullable = false)
    private long responseTimeMs;

    private String contentType;

    private String server;

    private int responseSize;

    @Column(length = 1000)
    private String securityHeadersPresent;

    @Column(length = 1000)
    private String securityHeadersMissing;

    @Column(nullable = false)
    private int securityScore;

    @Column(nullable = false)
    private String riskLevel;

    @Column(nullable = false)
    private LocalDateTime scannedAt;

    // User who performed the scan
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public ScanResult() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public int getResponseSize() {
        return responseSize;
    }

    public void setResponseSize(int responseSize) {
        this.responseSize = responseSize;
    }

    public String getSecurityHeadersPresent() {
        return securityHeadersPresent;
    }

    public void setSecurityHeadersPresent(String securityHeadersPresent) {
        this.securityHeadersPresent = securityHeadersPresent;
    }

    public String getSecurityHeadersMissing() {
        return securityHeadersMissing;
    }

    public void setSecurityHeadersMissing(String securityHeadersMissing) {
        this.securityHeadersMissing = securityHeadersMissing;
    }

    public int getSecurityScore() {
        return securityScore;
    }

    public void setSecurityScore(int securityScore) {
        this.securityScore = securityScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}