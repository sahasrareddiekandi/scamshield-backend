package com.scamshield.service;

import com.scamshield.dto.AdminAnalyticsResponse;
import com.scamshield.dto.AnalysisResponse;
import com.scamshield.dto.InsightsResponse;
import com.scamshield.entity.ContentType;
import com.scamshield.entity.ReportStatus;
import com.scamshield.entity.RiskLevel;
import com.scamshield.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class InsightsService {

    private final AnalysisRepository analysisRepository;
    private final AnalysisIndicatorRepository indicatorRepository;
    private final ReportedContentRepository reportedContentRepository;
    private final ThreatDataRepository threatDataRepository;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final UrlAnalysisService urlAnalysisService;

    public InsightsService(AnalysisRepository analysisRepository,
                           AnalysisIndicatorRepository indicatorRepository,
                           ReportedContentRepository reportedContentRepository,
                           ThreatDataRepository threatDataRepository,
                           UserRepository userRepository,
                           AuditLogRepository auditLogRepository,
                           UrlAnalysisService urlAnalysisService) {
        this.analysisRepository = analysisRepository;
        this.indicatorRepository = indicatorRepository;
        this.reportedContentRepository = reportedContentRepository;
        this.threatDataRepository = threatDataRepository;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.urlAnalysisService = urlAnalysisService;
    }

    @Transactional(readOnly = true)
    public InsightsResponse getPublicInsights() {
        InsightsResponse res = new InsightsResponse();

        long low = analysisRepository.countByRiskLevel(RiskLevel.LOW);
        long med = analysisRepository.countByRiskLevel(RiskLevel.MEDIUM);
        long high = analysisRepository.countByRiskLevel(RiskLevel.HIGH);
        long total = low + med + high;

        res.setTotalAnalyses(total);
        res.setLowRiskCount(low);
        res.setMediumRiskCount(med);
        res.setHighRiskCount(high);
        res.setTotalReports(reportedContentRepository.count());

        Double avg = analysisRepository.calculateAverageRiskScore();
        res.setAverageRiskScore(avg != null ? Math.round(avg * 10.0) / 10.0 : 0.0);

        // Top scam types
        Map<String, Long> scamTypes = new LinkedHashMap<>();
        for (Object[] row : analysisRepository.countGroupedByScamType()) {
            if (row[0] != null && scamTypes.size() < 6) {
                scamTypes.put((String) row[0], ((Number) row[1]).longValue());
            }
        }
        res.setTopScamTypes(scamTypes);

        // Top indicator categories
        Map<String, Long> indicators = new LinkedHashMap<>();
        for (Object[] row : indicatorRepository.countGroupedByCategory()) {
            if (row[0] != null && indicators.size() < 6) {
                indicators.put((String) row[0], ((Number) row[1]).longValue());
            }
        }
        res.setTopIndicators(indicators);

        // Recent analyses
        List<AnalysisResponse> recent = analysisRepository.findTop10ByOrderByCreatedAtDesc()
                .stream()
                .map(a -> {
                    AnalysisResponse dto = new AnalysisResponse();
                    dto.setId(a.getId());
                    // Mask sensitive text partially in public insights
                    dto.setContent(maskContent(a.getContent(), a.getContentType()));
                    dto.setContentType(a.getContentType());
                    dto.setRiskLevel(a.getRiskLevel());
                    dto.setRiskScore(a.getRiskScore());
                    dto.setScamType(a.getScamType());
                    dto.setSummary(a.getSummary());
                    dto.setCreatedAt(a.getCreatedAt());
                    return dto;
                })
                .collect(Collectors.toList());
        res.setRecentAnalyses(recent);

        return res;
    }

    @Transactional(readOnly = true)
    public AdminAnalyticsResponse getAdminAnalytics() {
        AdminAnalyticsResponse res = new AdminAnalyticsResponse();

        res.setTotalUsers(userRepository.count());
        long low = analysisRepository.countByRiskLevel(RiskLevel.LOW);
        long med = analysisRepository.countByRiskLevel(RiskLevel.MEDIUM);
        long high = analysisRepository.countByRiskLevel(RiskLevel.HIGH);
        res.setTotalAnalyses(low + med + high);
        res.setTotalReports(reportedContentRepository.count());
        res.setPendingReports(reportedContentRepository.countByStatus(ReportStatus.PENDING));
        res.setTotalAuditLogs(auditLogRepository.count());

        Map<String, Long> riskDist = new LinkedHashMap<>();
        riskDist.put("LOW", low);
        riskDist.put("MEDIUM", med);
        riskDist.put("HIGH", high);
        res.setRiskDistribution(riskDist);

        Map<String, Long> contentDist = new LinkedHashMap<>();
        contentDist.put("MESSAGE", analysisRepository.countByContentType(ContentType.MESSAGE));
        contentDist.put("URL", analysisRepository.countByContentType(ContentType.URL));
        res.setContentTypeDistribution(contentDist);

        Map<String, Long> scamCategories = new LinkedHashMap<>();
        for (Object[] row : analysisRepository.countGroupedByScamType()) {
            if (row[0] != null && scamCategories.size() < 8) {
                scamCategories.put((String) row[0], ((Number) row[1]).longValue());
            }
        }
        res.setTopScamCategories(scamCategories);

        res.setTopThreatPatterns(threatDataRepository.findTop20ByOrderByDetectionCountDesc());

        return res;
    }

    private String maskContent(String content, ContentType type) {
        if (content == null || content.length() < 12) return content;
        if (type == ContentType.URL) {
            try {
                java.net.URI u = java.net.URI.create(urlAnalysisService.normalizeUrl(content));
                return u.getHost() + "/...";
            } catch (Exception e) {
                return content.substring(0, 10) + "...";
            }
        }
        return content.substring(0, Math.min(30, content.length())) + "...";
    }
}
