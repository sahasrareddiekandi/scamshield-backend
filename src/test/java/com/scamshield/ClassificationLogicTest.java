package com.scamshield;

import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.RiskLevel;
import com.scamshield.service.MessageAnalysisService;
import com.scamshield.service.RiskScoringEngine;
import com.scamshield.service.UrlAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ClassificationLogicTest {

    private UrlAnalysisService urlAnalysisService;
    private MessageAnalysisService messageAnalysisService;
    private RiskScoringEngine riskScoringEngine;

    @BeforeEach
    void setUp() {
        riskScoringEngine = new RiskScoringEngine();
        urlAnalysisService = new UrlAnalysisService();
        messageAnalysisService = new MessageAnalysisService(urlAnalysisService);
    }

    private void printResult(String category, String input, int score, RiskLevel riskLevel, List<AnalysisIndicator> indicators) {
        System.out.println("==================================================");
        System.out.println("CATEGORY: " + category);
        System.out.println("INPUT: " + input);
        System.out.println("SCORE: " + score);
        System.out.println("RISK LEVEL: " + riskLevel);
        System.out.println("DETECTED REASONS:");
        if (indicators.isEmpty()) {
            System.out.println("  - None (Clean Content)");
        } else {
            for (AnalysisIndicator ind : indicators) {
                System.out.println("  - [" + ind.getCategory() + "] " + ind.getDescription() + " (weight: " + ind.getWeight() + ", severity: " + ind.getSeverity() + ")");
            }
        }
        System.out.println("==================================================");
    }

    // ==========================================
    // HIGH-RISK MESSAGE EXAMPLES
    // ==========================================

    @Test
    @DisplayName("HIGH-Risk Message 1: Bank blocked + OTP request")
    void testHighRiskMessage1() {
        String input = "Your bank account will be blocked today. Verify your account immediately using this link and enter your OTP.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("HIGH-Risk Message 2: Prize win + processing fee")
    void testHighRiskMessage2() {
        String input = "Congratulations! You won a ₹50,000 prize. Pay ₹999 processing fee immediately to claim your prize.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("HIGH-Risk Message 3: KYC expired + banking password & OTP")
    void testHighRiskMessage3() {
        String input = "Your KYC has expired. Click the link below and enter your banking password and OTP.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    // ==========================================
    // HIGH-RISK URL EXAMPLES
    // ==========================================

    @Test
    @DisplayName("HIGH-Risk URL 1: secure-bank-verify-login spoofing hostname")
    void testHighRiskUrl1() {
        String input = "https://secure-bank-verify-login.example.com";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("HIGH-Risk URL 2: HTTP shortened URL with verify-bank-otp")
    void testHighRiskUrl2() {
        String input = "http://bit.ly/verify-bank-otp";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("HIGH-Risk URL 3: account-suspended-login hostname")
    void testHighRiskUrl3() {
        String input = "http://account-suspended-login.example.com";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("HIGH-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.HIGH, level);
        assertTrue(result.getCalculatedScore() >= 70, "Score should be in HIGH range (70-100), but was: " + result.getCalculatedScore());
    }

    // ==========================================
    // MEDIUM-RISK MESSAGE EXAMPLES
    // ==========================================

    @Test
    @DisplayName("MEDIUM-Risk Message 1: Account verification soon review details")
    void testMediumRiskMessage1() {
        String input = "Your account needs verification soon. Please review your account details.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("MEDIUM-Risk Message 2: Limited-time offer with link")
    void testMediumRiskMessage2() {
        String input = "You have a limited-time offer. Click the link to learn more.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("MEDIUM-Risk Message 3: Subscription expiring soon review payment details")
    void testMediumRiskMessage3() {
        String input = "Your subscription is expiring soon. Please review your payment details.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    // ==========================================
    // MEDIUM-RISK URL EXAMPLES
    // ==========================================

    @Test
    @DisplayName("MEDIUM-Risk URL 1: example.com/account/verify")
    void testMediumRiskUrl1() {
        String input = "https://example.com/account/verify";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("MEDIUM-Risk URL 2: example.com/offer")
    void testMediumRiskUrl2() {
        String input = "https://example.com/offer";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("MEDIUM-Risk URL 3: example.com/update")
    void testMediumRiskUrl3() {
        String input = "https://example.com/update";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("MEDIUM-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.MEDIUM, level);
        assertTrue(result.getCalculatedScore() >= 40 && result.getCalculatedScore() <= 69,
                "Score should be in MEDIUM range (40-69), but was: " + result.getCalculatedScore());
    }

    // ==========================================
    // LOW-RISK MESSAGE EXAMPLES
    // ==========================================

    @Test
    @DisplayName("LOW-Risk Message 1: Hello greeting")
    void testLowRiskMessage1() {
        String input = "Hello, how are you today?";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("LOW-Risk Message 2: Meeting scheduled")
    void testLowRiskMessage2() {
        String input = "Your meeting is scheduled for 3 PM tomorrow.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("LOW-Risk Message 3: Order delivered")
    void testLowRiskMessage3() {
        String input = "Your order has been delivered successfully.";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK MESSAGE", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }

    // ==========================================
    // LOW-RISK URL EXAMPLES
    // ==========================================

    @Test
    @DisplayName("LOW-Risk URL 1: google.com")
    void testLowRiskUrl1() {
        String input = "https://www.google.com";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("LOW-Risk URL 2: wikipedia.org")
    void testLowRiskUrl2() {
        String input = "https://www.wikipedia.org";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }

    @Test
    @DisplayName("LOW-Risk URL 3: microsoft.com")
    void testLowRiskUrl3() {
        String input = "https://www.microsoft.com";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(input);
        RiskLevel level = riskScoringEngine.determineRiskLevel(result.getCalculatedScore(), result.getIndicators());

        printResult("LOW-RISK URL", input, result.getCalculatedScore(), level, result.getIndicators());

        assertEquals(RiskLevel.LOW, level);
        assertTrue(result.getCalculatedScore() >= 0 && result.getCalculatedScore() <= 39,
                "Score should be in LOW range (0-39), but was: " + result.getCalculatedScore());
    }
}
