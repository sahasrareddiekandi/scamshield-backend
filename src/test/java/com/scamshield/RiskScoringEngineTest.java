package com.scamshield;

import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.RiskLevel;
import com.scamshield.service.RiskScoringEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RiskScoringEngineTest {

    private RiskScoringEngine riskScoringEngine;

    @BeforeEach
    void setUp() {
        riskScoringEngine = new RiskScoringEngine();
    }

    @Test
    void testDetermineRiskLevel_Low() {
        assertEquals(RiskLevel.LOW, riskScoringEngine.determineRiskLevel(0));
        assertEquals(RiskLevel.LOW, riskScoringEngine.determineRiskLevel(15));
        assertEquals(RiskLevel.LOW, riskScoringEngine.determineRiskLevel(39));
    }

    @Test
    void testDetermineRiskLevel_Medium() {
        assertEquals(RiskLevel.MEDIUM, riskScoringEngine.determineRiskLevel(40));
        assertEquals(RiskLevel.MEDIUM, riskScoringEngine.determineRiskLevel(55));
        assertEquals(RiskLevel.MEDIUM, riskScoringEngine.determineRiskLevel(69));
    }

    @Test
    void testDetermineRiskLevel_High() {
        assertEquals(RiskLevel.HIGH, riskScoringEngine.determineRiskLevel(70));
        assertEquals(RiskLevel.HIGH, riskScoringEngine.determineRiskLevel(88));
        assertEquals(RiskLevel.HIGH, riskScoringEngine.determineRiskLevel(100));
    }

    @Test
    void testDetermineRiskLevel_Clamping() {
        assertEquals(0, riskScoringEngine.normalizeScore(-10));
        assertEquals(100, riskScoringEngine.normalizeScore(150));
        assertEquals(RiskLevel.LOW, riskScoringEngine.determineRiskLevel(-5));
        assertEquals(RiskLevel.HIGH, riskScoringEngine.determineRiskLevel(120));
    }

    @Test
    void testDetermineRiskLevel_IndicatorOverride() {
        List<AnalysisIndicator> indicators = List.of(
                new AnalysisIndicator("CREDENTIAL_HARVESTING", "Solicitation of OTP", RiskLevel.HIGH, 35)
        );
        // Even with score 35, high severity indicator must ensure HIGH risk
        assertEquals(RiskLevel.HIGH, riskScoringEngine.determineRiskLevel(35, indicators));
    }

    @Test
    void testGenerateSafetyAdvice_HighRisk() {
        List<AnalysisIndicator> indicators = List.of(
                new AnalysisIndicator("CREDENTIAL_HARVESTING", "Solicitation of OTP", RiskLevel.HIGH, 35),
                new AnalysisIndicator("PAYMENT_REQUEST", "Crypto demand", RiskLevel.HIGH, 30)
        );

        List<String> advice = riskScoringEngine.generateSafetyAdvice(RiskLevel.HIGH, indicators);
        assertNotNull(advice);
        assertFalse(advice.isEmpty());
        assertTrue(advice.stream().anyMatch(a -> a.contains("Never share OTPs")));
        assertTrue(advice.stream().anyMatch(a -> a.contains("send money")));
    }

    @Test
    void testCalculateConfidence() {
        List<AnalysisIndicator> indicators = List.of(
                new AnalysisIndicator("URGENCY_LANGUAGE", "Immediate action", RiskLevel.HIGH, 25)
        );
        double confidence = riskScoringEngine.calculateConfidence(80, indicators);
        assertTrue(confidence >= 0.70 && confidence <= 0.99);
    }
}
