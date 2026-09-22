package com.pruthviraj.api_sentinel.scanner;

public class OwaspFinding {

    private String category;
    private String title;
    private String severity;
    private String status;
    private String description;
    private String recommendation;

    public OwaspFinding() {
    }

    public OwaspFinding(
            String category,
            String title,
            String severity,
            String status,
            String description,
            String recommendation) {

        this.category = category;
        this.title = title;
        this.severity = severity;
        this.status = status;
        this.description = description;
        this.recommendation = recommendation;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }
}