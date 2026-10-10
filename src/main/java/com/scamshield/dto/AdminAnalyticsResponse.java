package com.scamshield.dto;

import com.scamshield.entity.ThreatData;

import java.util.List;
import java.util.Map;

public class AdminAnalyticsResponse {
    private long totalUsers;
    private long totalAnalyses;
    private long totalReports;
    private long pendingReports;
    private long totalAuditLogs;
    private Map<String, Long> riskDistribution;
    private Map<String, Long> contentTypeDistribution;
    private Map<String, Long> topScamCategories;
    private List<ThreatData> topThreatPatterns;

    public AdminAnalyticsResponse() {}

    public long getTotalUsers() {
        return totalUsers;
    }

    public void setTotalUsers(long totalUsers) {
        this.totalUsers = totalUsers;
    }

    public long getTotalAnalyses() {
        return totalAnalyses;
    }

    public void setTotalAnalyses(long totalAnalyses) {
        this.totalAnalyses = totalAnalyses;
    }

    public long getTotalReports() {
        return totalReports;
    }

    public void setTotalReports(long totalReports) {
        this.totalReports = totalReports;
    }

    public long getPendingReports() {
        return pendingReports;
    }

    public void setPendingReports(long pendingReports) {
        this.pendingReports = pendingReports;
    }

    public long getTotalAuditLogs() {
        return totalAuditLogs;
    }

    public void setTotalAuditLogs(long totalAuditLogs) {
        this.totalAuditLogs = totalAuditLogs;
    }

    public Map<String, Long> getRiskDistribution() {
        return riskDistribution;
    }

    public void setRiskDistribution(Map<String, Long> riskDistribution) {
        this.riskDistribution = riskDistribution;
    }

    public Map<String, Long> getContentTypeDistribution() {
        return contentTypeDistribution;
    }

    public void setContentTypeDistribution(Map<String, Long> contentTypeDistribution) {
        this.contentTypeDistribution = contentTypeDistribution;
    }

    public Map<String, Long> getTopScamCategories() {
        return topScamCategories;
    }

    public void setTopScamCategories(Map<String, Long> topScamCategories) {
        this.topScamCategories = topScamCategories;
    }

    public List<ThreatData> getTopThreatPatterns() {
        return topThreatPatterns;
    }

    public void setTopThreatPatterns(List<ThreatData> topThreatPatterns) {
        this.topThreatPatterns = topThreatPatterns;
    }
}
