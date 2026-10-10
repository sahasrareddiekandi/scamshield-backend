package com.scamshield.dto;

import java.util.ArrayList;
import java.util.List;

public class GeminiAnalysisDto {
    private String riskLevel;
    private Double confidence;
    private String scamType;
    private String summary;
    private List<String> indicators = new ArrayList<>();
    private List<String> socialEngineeringTechniques = new ArrayList<>();
    private List<String> safetyAdvice = new ArrayList<>();

    public GeminiAnalysisDto() {}

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Double getConfidence() {
        return confidence;
    }

    public void setConfidence(Double confidence) {
        this.confidence = confidence;
    }

    public String getScamType() {
        return scamType;
    }

    public void setScamType(String scamType) {
        this.scamType = scamType;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<String> indicators) {
        this.indicators = indicators;
    }

    public List<String> getSocialEngineeringTechniques() {
        return socialEngineeringTechniques;
    }

    public void setSocialEngineeringTechniques(List<String> socialEngineeringTechniques) {
        this.socialEngineeringTechniques = socialEngineeringTechniques;
    }

    public List<String> getSafetyAdvice() {
        return safetyAdvice;
    }

    public void setSafetyAdvice(List<String> safetyAdvice) {
        this.safetyAdvice = safetyAdvice;
    }
}
