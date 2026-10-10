package com.scamshield.dto;

import com.scamshield.entity.ContentType;
import com.scamshield.entity.RiskLevel;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class AnalysisResponse {
    private Long id;
    private String content;
    private ContentType contentType;
    private RiskLevel riskLevel;
    private int riskScore;
    private double confidence;
    private String scamType;
    private String summary;
    private boolean geminiUsed;
    private List<IndicatorDto> indicators = new ArrayList<>();
    private List<String> safetyAdvice = new ArrayList<>();
    private List<String> socialEngineeringTechniques = new ArrayList<>();
    private UrlDetailsDto urlDetails;
    private LocalDateTime createdAt;

    public AnalysisResponse() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public ContentType getContentType() {
        return contentType;
    }

    public void setContentType(ContentType contentType) {
        this.contentType = contentType;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
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

    public boolean isGeminiUsed() {
        return geminiUsed;
    }

    public void setGeminiUsed(boolean geminiUsed) {
        this.geminiUsed = geminiUsed;
    }

    public List<IndicatorDto> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<IndicatorDto> indicators) {
        this.indicators = indicators;
    }

    public List<String> getSafetyAdvice() {
        return safetyAdvice;
    }

    public void setSafetyAdvice(List<String> safetyAdvice) {
        this.safetyAdvice = safetyAdvice;
    }

    public List<String> getSocialEngineeringTechniques() {
        return socialEngineeringTechniques;
    }

    public void setSocialEngineeringTechniques(List<String> socialEngineeringTechniques) {
        this.socialEngineeringTechniques = socialEngineeringTechniques;
    }

    public UrlDetailsDto getUrlDetails() {
        return urlDetails;
    }

    public void setUrlDetails(UrlDetailsDto urlDetails) {
        this.urlDetails = urlDetails;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
