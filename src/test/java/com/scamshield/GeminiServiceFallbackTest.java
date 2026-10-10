package com.scamshield;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamshield.config.GeminiProperties;
import com.scamshield.dto.GeminiAnalysisDto;
import com.scamshield.service.GeminiService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.client.RestTemplateBuilder;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GeminiServiceFallbackTest {

    @Test
    void testGeminiService_FallbackWhenKeyNotConfigured() {
        GeminiProperties properties = new GeminiProperties(); // default apiKey is empty
        ObjectMapper mapper = new ObjectMapper();
        RestTemplateBuilder builder = new RestTemplateBuilder();

        GeminiService geminiService = new GeminiService(properties, builder, mapper);

        Optional<GeminiAnalysisDto> result = geminiService.analyzeWithGemini(
                "Verify your account now", "message", 50, Collections.emptyList()
        );

        // When GEMINI_API_KEY is not set or empty, gracefully returns empty Optional and doesn't crash
        assertTrue(result.isEmpty(), "Should gracefully return Optional.empty() without throwing exceptions");
    }
}
