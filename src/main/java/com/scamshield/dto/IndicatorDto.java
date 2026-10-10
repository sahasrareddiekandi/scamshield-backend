package com.scamshield.dto;

import com.scamshield.entity.RiskLevel;

public class IndicatorDto {
    private String category;
    private String description;
    private RiskLevel severity;
    private int weight;

    public IndicatorDto() {}

    public IndicatorDto(String category, String description, RiskLevel severity, int weight) {
        this.category = category;
        this.description = description;
        this.severity = severity;
        this.weight = weight;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public RiskLevel getSeverity() {
        return severity;
    }

    public void setSeverity(RiskLevel severity) {
        this.severity = severity;
    }

    public int getWeight() {
        return weight;
    }

    public void setWeight(int weight) {
        this.weight = weight;
    }
}
