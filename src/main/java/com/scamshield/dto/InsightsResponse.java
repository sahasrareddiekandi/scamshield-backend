package com.scamshield.dto;

import java.util.List;
import java.util.Map;

public class InsightsResponse {
    private long totalAnalyses;
    private long lowRiskCount;
    private long mediumRiskCount;
    private long highRiskCount;
    private long totalReports;
    private double averageRiskScore;
    private Map<String, Long> topScamTypes;
    private Map<String, Long> topIndicators;
    private List<AnalysisResponse> recentAnalyses;

    public InsightsResponse() {}

    public long getTotalAnalyses() {
        return totalAnalyses;
    }

    public void setTotalAnalyses(long totalAnalyses) {
        this.totalAnalyses = totalAnalyses;
    }

    public long getLowRiskCount() {
        return lowRiskCount;
    }

    public void setLowRiskCount(long lowRiskCount) {
        this.lowRiskCount = lowRiskCount;
    }

    public long getMediumRiskCount() {
        return mediumRiskCount;
    }

    public void setMediumRiskCount(long mediumRiskCount) {
        this.mediumRiskCount = mediumRiskCount;
    }

    public long getHighRiskCount() {
        return highRiskCount;
    }

    public void setHighRiskCount(long highRiskCount) {
        this.highRiskCount = highRiskCount;
    }

    public long getTotalReports() {
        return totalReports;
    }

    public void setTotalReports(long totalReports) {
        this.totalReports = totalReports;
    }

    public double getAverageRiskScore() {
        return averageRiskScore;
    }

    public void setAverageRiskScore(double averageRiskScore) {
        this.averageRiskScore = averageRiskScore;
    }

    public Map<String, Long> getTopScamTypes() {
        return topScamTypes;
    }

    public void setTopScamTypes(Map<String, Long> topScamTypes) {
        this.topScamTypes = topScamTypes;
    }

    public Map<String, Long> getTopIndicators() {
        return topIndicators;
    }

    public void setTopIndicators(Map<String, Long> topIndicators) {
        this.topIndicators = topIndicators;
    }

    public List<AnalysisResponse> getRecentAnalyses() {
        return recentAnalyses;
    }

    public void setRecentAnalyses(List<AnalysisResponse> recentAnalyses) {
        this.recentAnalyses = recentAnalyses;
    }
}
