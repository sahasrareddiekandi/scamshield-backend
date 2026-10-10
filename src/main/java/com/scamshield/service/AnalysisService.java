package com.scamshield.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.scamshield.dto.AnalysisResponse;
import com.scamshield.dto.GeminiAnalysisDto;
import com.scamshield.dto.IndicatorDto;
import com.scamshield.dto.UrlDetailsDto;
import com.scamshield.entity.Analysis;
import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.ContentType;
import com.scamshield.entity.RiskLevel;
import com.scamshield.entity.ThreatData;
import com.scamshield.entity.User;
import com.scamshield.exception.ResourceNotFoundException;
import com.scamshield.repository.AnalysisRepository;
import com.scamshield.repository.ThreatDataRepository;
import com.scamshield.repository.UserRepository;
import com.scamshield.security.SecurityUtils;
import com.scamshield.util.HashUtils;

@Service
public class AnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(AnalysisService.class);

    private final MessageAnalysisService messageAnalysisService;
    private final UrlAnalysisService urlAnalysisService;
    private final RiskScoringEngine riskScoringEngine;
    private final GeminiService geminiService;
    private final CacheService cacheService;
    private final AuditLogService auditLogService;
    private final AnalysisRepository analysisRepository;
    private final ThreatDataRepository threatDataRepository;
    private final UserRepository userRepository;

    public AnalysisService(MessageAnalysisService messageAnalysisService,
                           UrlAnalysisService urlAnalysisService,
                           RiskScoringEngine riskScoringEngine,
                           GeminiService geminiService,
                           CacheService cacheService,
                           AuditLogService auditLogService,
                           AnalysisRepository analysisRepository,
                           ThreatDataRepository threatDataRepository,
                           UserRepository userRepository) {
        this.messageAnalysisService = messageAnalysisService;
        this.urlAnalysisService = urlAnalysisService;
        this.riskScoringEngine = riskScoringEngine;
        this.geminiService = geminiService;
        this.cacheService = cacheService;
        this.auditLogService = auditLogService;
        this.analysisRepository = analysisRepository;
        this.threatDataRepository = threatDataRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public AnalysisResponse analyzeMessage(String messageText, String clientIp) {
        String cleanText = messageText.trim();
        String contentHash = HashUtils.sha256(cleanText);

        // 1. Check Redis / Memory cache
        AnalysisResponse cached = cacheService.get("analysis:" + contentHash, AnalysisResponse.class);
        if (cached != null) {
            logger.info("Returning cached analysis for hash: {}", contentHash);
            auditLogService.log("ANALYZE_MESSAGE_CACHE_HIT", getCurrentActor(), clientIp, "Analysis returned from cache");
            return cached;
        }

        // 2. Rule-Based Analysis
        MessageAnalysisService.MessageAnalysisResult ruleResult = messageAnalysisService.analyzeMessage(cleanText);
        int ruleScore = ruleResult.getCalculatedScore();
        List<AnalysisIndicator> indicators = new ArrayList<>(ruleResult.getIndicators());
        List<String> indicatorDescriptions = indicators.stream().map(AnalysisIndicator::getDescription).toList();

        // 3. Gemini AI Analysis Layer
        Optional<GeminiAnalysisDto> geminiResult = geminiService.analyzeWithGemini(
                cleanText, "message", ruleScore, indicatorDescriptions
        );

        // 4. Combined Risk Assessment
        CombinedAssessment combined = synthesizeAssessment(
                ContentType.MESSAGE, ruleScore, ruleResult.getPrimaryScamCategory(), indicators, geminiResult
        );

        // 5. Build and save Analysis entity
        Analysis analysis = new Analysis();
        analysis.setContent(cleanText);
        analysis.setContentType(ContentType.MESSAGE);
        analysis.setContentHash(contentHash);
        analysis.setRiskScore(combined.finalScore);
        analysis.setRiskLevel(combined.riskLevel);
        analysis.setConfidence(combined.confidence);
        analysis.setScamType(combined.scamType);
        analysis.setSummary(combined.summary);
        analysis.setGeminiUsed(geminiResult.isPresent());
        analysis.setSafetyAdvice(combined.safetyAdvice);
        analysis.setSocialEngineeringTechniques(combined.socialEngineeringTechniques);

        getCurrentUser().ifPresent(analysis::setUser);

        for (AnalysisIndicator ind : indicators) {
            analysis.addIndicator(ind);
        }

        Analysis saved = analysisRepository.save(analysis);

        // 6. Threat Telemetry update
        updateThreatTelemetry(indicators);

        // 7. Audit log
        auditLogService.log("ANALYZE_MESSAGE", getCurrentActor(), clientIp,
                String.format("Analyzed message: score=%d, level=%s, gemini=%b",
                        saved.getRiskScore(), saved.getRiskLevel(), saved.isGeminiUsed()));

        AnalysisResponse response = mapToResponse(saved, null);

        // 8. Cache result for 1 hour
        cacheService.set("analysis:" + contentHash, response, 3600);

        return response;
    }

    @Transactional
    public AnalysisResponse analyzeUrl(String rawUrl, String clientIp) {
        String normalizedUrl = urlAnalysisService.normalizeUrl(rawUrl);
        String contentHash = HashUtils.sha256(normalizedUrl);

        // 1. Check Redis / Memory cache
        AnalysisResponse cached = cacheService.get("analysis:" + contentHash, AnalysisResponse.class);
        if (cached != null) {
            logger.info("Returning cached URL analysis for hash: {}", contentHash);
            auditLogService.log("ANALYZE_URL_CACHE_HIT", getCurrentActor(), clientIp, "URL analysis returned from cache");
            return cached;
        }

        // 2. Rule-Based URL Analysis
        UrlAnalysisService.UrlAnalysisResult ruleResult = urlAnalysisService.analyzeUrl(normalizedUrl);
        int ruleScore = ruleResult.getCalculatedScore();
        List<AnalysisIndicator> indicators = new ArrayList<>(ruleResult.getIndicators());
        List<String> indicatorDescriptions = indicators.stream().map(AnalysisIndicator::getDescription).toList();

        // 3. Gemini AI Analysis Layer
        Optional<GeminiAnalysisDto> geminiResult = geminiService.analyzeWithGemini(
                normalizedUrl, "URL", ruleScore, indicatorDescriptions
        );

        // 4. Combined Risk Assessment
        String defaultType;
        if (ruleScore >= 70) {
            defaultType = "Phishing / Malicious URL";
        } else if (ruleScore >= 40) {
            defaultType = "Suspicious URL";
        } else {
            defaultType = "Safe Link";
        }
        CombinedAssessment combined = synthesizeAssessment(
                ContentType.URL, ruleScore, defaultType, indicators, geminiResult
        );

        // 5. Build and save Analysis entity
        Analysis analysis = new Analysis();
        analysis.setContent(normalizedUrl);
        analysis.setContentType(ContentType.URL);
        analysis.setContentHash(contentHash);
        analysis.setRiskScore(combined.finalScore);
        analysis.setRiskLevel(combined.riskLevel);
        analysis.setConfidence(combined.confidence);
        analysis.setScamType(combined.scamType);
        analysis.setSummary(combined.summary);
        analysis.setGeminiUsed(geminiResult.isPresent());
        analysis.setSafetyAdvice(combined.safetyAdvice);
        analysis.setSocialEngineeringTechniques(combined.socialEngineeringTechniques);

        getCurrentUser().ifPresent(analysis::setUser);

        for (AnalysisIndicator ind : indicators) {
            analysis.addIndicator(ind);
        }

        Analysis saved = analysisRepository.save(analysis);

        // 6. Threat Telemetry update
        updateThreatTelemetry(indicators);

        // 7. Audit log
        auditLogService.log("ANALYZE_URL", getCurrentActor(), clientIp,
                String.format("Analyzed URL: score=%d, level=%s, gemini=%b",
                        saved.getRiskScore(), saved.getRiskLevel(), saved.isGeminiUsed()));

        AnalysisResponse response = mapToResponse(saved, ruleResult.getDetails());

        // 8. Cache result
        cacheService.set("analysis:" + contentHash, response, 3600);

        return response;
    }

    private static class CombinedAssessment {
        int finalScore;
        RiskLevel riskLevel;
        double confidence;
        String scamType;
        String summary;
        List<String> safetyAdvice;
        List<String> socialEngineeringTechniques;
    }

    private CombinedAssessment synthesizeAssessment(
            ContentType contentType,
            int ruleScore,
            String ruleScamType,
            List<AnalysisIndicator> indicators,
            Optional<GeminiAnalysisDto> geminiResult) {

        CombinedAssessment assessment = new CombinedAssessment();
        int normalizedRuleScore = riskScoringEngine.normalizeScore(ruleScore);
        RiskLevel ruleLevel = riskScoringEngine.determineRiskLevel(normalizedRuleScore, indicators);
        boolean hasHighRuleAlert = (ruleLevel == RiskLevel.HIGH) ||
                (indicators != null && indicators.stream().anyMatch(i -> i.getSeverity() == RiskLevel.HIGH));
        boolean hasMediumRuleAlert = (ruleLevel == RiskLevel.MEDIUM) ||
                (indicators != null && indicators.stream().anyMatch(i -> i.getSeverity() == RiskLevel.MEDIUM));

        if (geminiResult.isPresent()) {
            GeminiAnalysisDto ai = geminiResult.get();
            RiskLevel aiLevel;
            try {
                aiLevel = RiskLevel.valueOf(ai.getRiskLevel().toUpperCase());
            } catch (Exception e) {
                aiLevel = RiskLevel.LOW;
            }

            int geminiNumeric = switch (aiLevel) {
                case HIGH -> 85;
                case MEDIUM -> 50;
                case LOW -> 15;
            };

            RiskLevel finalLevel;
            int finalScore;

            // Strict Severity Priority: HIGH > MEDIUM > LOW
            // Deterministic rules must override weaker AI classification.
            // AI must not downgrade medium rule alerts to LOW.
            if (hasHighRuleAlert) {
                finalLevel = RiskLevel.HIGH;
                finalScore = Math.max(70, normalizedRuleScore);
            } else if (aiLevel == RiskLevel.HIGH) {
                if (normalizedRuleScore > 0 || (indicators != null && !indicators.isEmpty())) {
                    finalLevel = RiskLevel.HIGH;
                    finalScore = Math.max(70, (int) Math.round((normalizedRuleScore * 0.50) + (geminiNumeric * 0.50)));
                } else {
                    // Safe content (0 rule score and 0 indicators) -> AI alone cannot force false HIGH
                    finalLevel = RiskLevel.LOW;
                    finalScore = normalizedRuleScore;
                }
            } else if (hasMediumRuleAlert) {
                finalLevel = RiskLevel.MEDIUM;
                finalScore = Math.min(69, Math.max(40, normalizedRuleScore));
            } else if (aiLevel == RiskLevel.MEDIUM) {
                if (normalizedRuleScore > 0 || (indicators != null && !indicators.isEmpty())) {
                    finalLevel = RiskLevel.MEDIUM;
                    finalScore = Math.min(69, Math.max(40, (int) Math.round((normalizedRuleScore * 0.50) + (geminiNumeric * 0.50))));
                } else {
                    finalLevel = RiskLevel.LOW;
                    finalScore = normalizedRuleScore;
                }
            } else {
                finalLevel = RiskLevel.LOW;
                int combinedScore = (int) Math.round((normalizedRuleScore * 0.60) + (geminiNumeric * 0.40));
                finalScore = Math.min(39, Math.max(0, combinedScore));
            }

            assessment.finalScore = riskScoringEngine.normalizeScore(finalScore);
            assessment.riskLevel = finalLevel;
            assessment.confidence = Math.max(riskScoringEngine.calculateConfidence(assessment.finalScore, indicators), ai.getConfidence());
            assessment.scamType = (ai.getScamType() != null && !ai.getScamType().isBlank()) ? ai.getScamType() : ruleScamType;
            assessment.summary = ai.getSummary();
            assessment.socialEngineeringTechniques = ai.getSocialEngineeringTechniques();

            // Blend safety advice
            Set<String> adviceSet = new LinkedHashSet<>();
            if (ai.getSafetyAdvice() != null) {
                adviceSet.addAll(ai.getSafetyAdvice());
            }
            adviceSet.addAll(riskScoringEngine.generateSafetyAdvice(assessment.riskLevel, indicators));
            assessment.safetyAdvice = new ArrayList<>(adviceSet);

            logger.info("SYNTHESIZED_ASSESSMENT (Gemini): contentType={}, ruleScore={}, aiLevel={}, finalScore={}, finalLevel={}, indicators={}",
                    contentType, normalizedRuleScore, aiLevel, assessment.finalScore, assessment.riskLevel,
                    indicators != null ? indicators.stream().map(AnalysisIndicator::getCategory).toList() : List.of());

        } else {
            // 100% Rule-Based Assessment
            int score = normalizedRuleScore;
            if (hasHighRuleAlert) {
                score = Math.max(70, score);
            }
            assessment.finalScore = riskScoringEngine.normalizeScore(score);
            assessment.riskLevel = riskScoringEngine.determineRiskLevel(assessment.finalScore, indicators);
            assessment.confidence = riskScoringEngine.calculateConfidence(assessment.finalScore, indicators);
            assessment.scamType = ruleScamType;
            assessment.summary = riskScoringEngine.generateSummary(assessment.riskLevel, assessment.finalScore, ruleScamType, indicators);
            assessment.safetyAdvice = riskScoringEngine.generateSafetyAdvice(assessment.riskLevel, indicators);
            assessment.socialEngineeringTechniques = deriveSocialEngineeringFromIndicators(indicators);

            logger.info("SYNTHESIZED_ASSESSMENT (Rule-Only): contentType={}, rawScore={}, finalScore={}, finalLevel={}, indicators={}",
                    contentType, ruleScore, assessment.finalScore, assessment.riskLevel,
                    indicators != null ? indicators.stream().map(AnalysisIndicator::getCategory).toList() : List.of());
        }

        return assessment;
    }

    private List<String> deriveSocialEngineeringFromIndicators(List<AnalysisIndicator> indicators) {
        List<String> techniques = new ArrayList<>();
        for (AnalysisIndicator i : indicators) {
            if (i.getCategory().contains("URGENCY")) {
                techniques.add("Manufactured Urgency: Creating artificial time-pressure to impair critical evaluation.");
            } else if (i.getCategory().contains("AUTHORITY")) {
                techniques.add("Authority Impersonation: Pretending to be official institutions to demand compliance.");
            } else if (i.getCategory().contains("PRIZE")) {
                techniques.add("Greed / False Reward: Offering improbable payouts to solicit fees or personal credentials.");
            } else if (i.getCategory().contains("CREDENTIAL")) {
                techniques.add("Credential Phishing: Coercing victim into forfeiting multi-factor auth or security codes.");
            }
        }
        if (techniques.isEmpty()) {
            techniques.add("Standard Contextual Evaluation: No overt psychological manipulation triggers identified.");
        }
        return techniques;
    }

    private void updateThreatTelemetry(List<AnalysisIndicator> indicators) {
        for (AnalysisIndicator indicator : indicators) {
            try {
                Optional<ThreatData> existing = threatDataRepository.findByPattern(indicator.getCategory());
                if (existing.isPresent()) {
                    ThreatData td = existing.get();
                    td.incrementDetections();
                    threatDataRepository.save(td);
                } else {
                    ThreatData newTd = new ThreatData(
                            "SIGNATURE",
                            indicator.getCategory(),
                            indicator.getCategory(),
                            indicator.getSeverity(),
                            indicator.getDescription()
                    );
                    threatDataRepository.save(newTd);
                }
            } catch (Exception e) {
                logger.debug("Telemetry logging skipped: {}", e.getMessage());
            }
        }
    }

    @Transactional(readOnly = true)
    public List<AnalysisResponse> getUserAnalyses() {
        Optional<User> userOpt = getCurrentUser();
        if (userOpt.isEmpty()) {
            return Collections.emptyList();
        }
        return analysisRepository.findByUserOrderByCreatedAtDesc(userOpt.get())
                .stream()
                .map(a -> mapToResponse(a, null))
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Page<AnalysisResponse> getUserAnalysesPaged(Pageable pageable) {
        Optional<User> userOpt = getCurrentUser();
        if (userOpt.isEmpty()) {
            return Page.empty();
        }
        return analysisRepository.findByUserOrderByCreatedAtDesc(userOpt.get(), pageable)
                .map(a -> mapToResponse(a, null));
    }

    @Transactional(readOnly = true)
    public AnalysisResponse getAnalysisById(Long id) {
        Analysis analysis = analysisRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analysis not found with ID: " + id));

        UrlDetailsDto urlDetails = null;
        if (analysis.getContentType() == ContentType.URL) {
            urlDetails = urlAnalysisService.analyzeUrl(analysis.getContent()).getDetails();
        }

        return mapToResponse(analysis, urlDetails);
    }

    public AnalysisResponse mapToResponse(Analysis entity, UrlDetailsDto urlDetails) {
        AnalysisResponse dto = new AnalysisResponse();
        dto.setId(entity.getId());
        dto.setContent(entity.getContent());
        dto.setContentType(entity.getContentType());
        dto.setRiskLevel(entity.getRiskLevel());
        dto.setRiskScore(entity.getRiskScore());
        dto.setConfidence(entity.getConfidence());
        dto.setScamType(entity.getScamType());
        dto.setSummary(entity.getSummary());
        dto.setGeminiUsed(entity.isGeminiUsed());
        dto.setSafetyAdvice(entity.getSafetyAdvice());
        dto.setSocialEngineeringTechniques(entity.getSocialEngineeringTechniques());
        dto.setCreatedAt(entity.getCreatedAt());

        if (entity.getIndicators() != null) {
            dto.setIndicators(entity.getIndicators().stream().map(i ->
                    new IndicatorDto(i.getCategory(), i.getDescription(), i.getSeverity(), i.getWeight())
            ).collect(Collectors.toList()));
        }

        if (urlDetails == null && entity.getContentType() == ContentType.URL) {
            dto.setUrlDetails(urlAnalysisService.analyzeUrl(entity.getContent()).getDetails());
        } else {
            dto.setUrlDetails(urlDetails);
        }

        return dto;
    }

    private Optional<User> getCurrentUser() {
        return SecurityUtils.getCurrentUserEmail().flatMap(userRepository::findByEmail);
    }

    private String getCurrentActor() {
        return SecurityUtils.getCurrentUserEmail().orElse("ANONYMOUS");
    }
}
