package com.upwind.emailsecurity.model;

public class RiskSignal {

    private String category;
    private String severity;
    private String message;
    private int points;

    public RiskSignal() {
    }

    public RiskSignal(String category, String severity, String message, int points) {
        this.category = category;
        this.severity = severity;
        this.message = message;
        this.points = points;
    }

    public String getCategory() {
        return category;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }

    public int getPoints() {
        return points;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setPoints(int points) {
        this.points = points;
    }
}