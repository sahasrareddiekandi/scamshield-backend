package com.scamshield;

import com.scamshield.entity.RiskLevel;
import com.scamshield.service.UrlAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class UrlAnalysisServiceTest {

    private UrlAnalysisService urlAnalysisService;

    @BeforeEach
    void setUp() {
        urlAnalysisService = new UrlAnalysisService();
    }

    @Test
    void testAnalyzeUrl_SafeUrl() {
        String safeUrl = "https://github.com/torvalds/linux";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(safeUrl);

        assertTrue(result.getCalculatedScore() <= 30);
        assertTrue(result.getDetails().isHttps());
        assertFalse(result.getDetails().isIpAddress());
        assertFalse(result.getDetails().isHasSuspiciousTld());
    }

    @Test
    void testAnalyzeUrl_SuspiciousIpAddressHost() {
        String ipUrl = "http://185.220.101.4/secure/login";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(ipUrl);

        assertTrue(result.getCalculatedScore() >= 50);
        assertTrue(result.getDetails().isIpAddress());
        assertFalse(result.getDetails().isHttps());
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("URL_HOST")));
    }

    @Test
    void testAnalyzeUrl_BrandSpoofingAndDisreputableTld() {
        String phishingUrl = "http://paypal-security-verification.xyz/account/login?token=abc";
        UrlAnalysisService.UrlAnalysisResult result = urlAnalysisService.analyzeUrl(phishingUrl);

        assertTrue(result.getCalculatedScore() >= 70);
        assertTrue(result.getDetails().isHasSuspiciousTld());
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("BRAND_IMPERSONATION")));
        assertTrue(result.getIndicators().stream().anyMatch(i -> i.getCategory().equals("URL_DOMAIN")));
    }
}
