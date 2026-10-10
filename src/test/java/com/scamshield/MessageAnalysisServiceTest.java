package com.scamshield;

import com.scamshield.entity.RiskLevel;
import com.scamshield.service.MessageAnalysisService;
import com.scamshield.service.UrlAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MessageAnalysisServiceTest {

    private MessageAnalysisService messageAnalysisService;

    @BeforeEach
    void setUp() {
        UrlAnalysisService urlAnalysisService = new UrlAnalysisService();
        messageAnalysisService = new MessageAnalysisService(urlAnalysisService);
    }

    @Test
    void testAnalyzeMessage_LowRiskSafeMessage() {
        String safeText = "Hey team, just confirming our sync call scheduled for 3 PM today. See you all soon!";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(safeText);

        assertTrue(result.getCalculatedScore() <= 30);
        assertEquals("Clean / Low Risk", result.getPrimaryScamCategory());
        assertTrue(result.getIndicators().isEmpty());
    }

    @Test
    void testAnalyzeMessage_MediumRiskWarningMessage() {
        String mediumText = "Your quarterly billing notice is ready. Click the link to review your statement: https://portal.company.com/billing";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(mediumText);

        assertTrue(result.getCalculatedScore() > 0);
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().contains("CALL_TO_ACTION") || i.getCategory().contains("PHISHING")));
    }

    @Test
    void testAnalyzeMessage_HighRiskScamMessage() {
        String scamText = "URGENT NOTICE: Your bank account will be suspended within 24 hours due to suspicious activity. Immediately verify your account by sharing your OTP code or pay the $50 clearance fee via bitcoin: http://192.168.1.15/login";
        MessageAnalysisService.MessageAnalysisResult result = messageAnalysisService.analyzeMessage(scamText);

        assertTrue(result.getCalculatedScore() >= 71, "Score should be in HIGH risk range (>=71)");
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("URGENCY_LANGUAGE")));
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("PAYMENT_REQUEST")));
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("CREDENTIAL_HARVESTING")));
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("EMBEDDED_SUSPICIOUS_URL")));
    }
}
