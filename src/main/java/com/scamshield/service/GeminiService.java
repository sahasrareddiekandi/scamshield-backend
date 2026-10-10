package com.scamshield.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamshield.config.GeminiProperties;
import com.scamshield.dto.GeminiAnalysisDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.*;

@Service
public class GeminiService {

    private static final Logger logger = LoggerFactory.getLogger(GeminiService.class);

    private final GeminiProperties geminiProperties;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public GeminiService(GeminiProperties geminiProperties,
                         RestTemplateBuilder restTemplateBuilder,
                         ObjectMapper objectMapper) {
        this.geminiProperties = geminiProperties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplateBuilder
                .setConnectTimeout(Duration.ofMillis(geminiProperties.getTimeoutMs()))
                .setReadTimeout(Duration.ofMillis(geminiProperties.getTimeoutMs()))
                .build();
    }

    public Optional<GeminiAnalysisDto> analyzeWithGemini(String content, String contentType, int ruleScore, List<String> ruleIndicators) {
        if (!geminiProperties.isConfigured()) {
            logger.info("Gemini API key is not configured. Falling back transparently to rule-based analysis engine.");
            return Optional.empty();
        }

        try {
            String prompt = buildPrompt(content, contentType, ruleScore, ruleIndicators);
            String url = String.format("%s/%s:generateContent?key=%s",
                    geminiProperties.getApiUrl(),
                    geminiProperties.getModel(),
                    geminiProperties.getApiKey());

            Map<String, Object> textPart = Map.of("text", prompt);
            Map<String, Object> contents = Map.of("parts", List.of(textPart));
            Map<String, Object> generationConfig = Map.of(
                    "temperature", 0.2,
                    "responseMimeType", "application/json"
            );
            Map<String, Object> requestBody = Map.of(
                    "contents", List.of(contents),
                    "generationConfig", generationConfig
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseAndValidateGeminiResponse(response.getBody());
            } else {
                logger.warn("Gemini API returned non-200 status: {}", response.getStatusCode());
            }
        } catch (Exception e) {
            logger.warn("Gemini AI API call failed: {}. Continuing with rule-based engine.", e.getMessage());
        }

        return Optional.empty();
    }

    private String buildPrompt(String content, String contentType, int ruleScore, List<String> ruleIndicators) {
        return "You are ScamShield AI, an advanced cybersecurity analysis engine for scam and phishing detection.\n" +
                "Evaluate the following " + contentType + ".\n" +
                "Rule-Based Engine Preliminary Score: " + ruleScore + "/100\n" +
                "Rule-Based Identified Indicators: " + String.join("; ", ruleIndicators) + "\n\n" +
                "CONTENT TO ANALYZE:\n" +
                "\"\"\"\n" + content + "\n\"\"\"\n\n" +
                "Instructions:\n" +
                "1. Analyze contextual psychology, urgency, brand spoofing, monetary risk, credential theft, and deceit.\n" +
                "2. Classify risk level as exactly 'LOW', 'MEDIUM', or 'HIGH'.\n" +
                "3. Provide confidence between 0.50 and 0.99.\n" +
                "4. Identify the specific scam type (e.g. 'Bank Phishing', 'Crypto Investment Scam', 'Credential Harvesting', 'Lottery Fraud', 'Legitimate').\n" +
                "5. Provide 2-4 concise detected indicators.\n" +
                "6. Identify 1-3 psychological/social engineering techniques used (e.g. 'False Authority', 'Scarcity/Urgency', 'Greed Appeal', 'Fear of Consequences').\n" +
                "7. Provide 2-4 actionable safety advice steps for the user.\n\n" +
                "Respond ONLY with a valid JSON object matching this schema:\n" +
                "{\n" +
                "  \"riskLevel\": \"HIGH\",\n" +
                "  \"confidence\": 0.95,\n" +
                "  \"scamType\": \"Phishing\",\n" +
                "  \"summary\": \"Concise threat evaluation...\",\n" +
                "  \"indicators\": [\"...\", \"...\"],\n" +
                "  \"socialEngineeringTechniques\": [\"...\", \"...\"],\n" +
                "  \"safetyAdvice\": [\"...\", \"...\"]\n" +
                "}";
    }

    private Optional<GeminiAnalysisDto> parseAndValidateGeminiResponse(String responseJson) {
        try {
            JsonNode rootNode = objectMapper.readTree(responseJson);
            JsonNode candidates = rootNode.path("candidates");
            if (candidates.isEmpty()) {
                return Optional.empty();
            }

            JsonNode contentParts = candidates.get(0).path("content").path("parts");
            if (contentParts.isEmpty()) {
                return Optional.empty();
            }

            String rawText = contentParts.get(0).path("text").asText();
            if (rawText == null || rawText.isBlank()) {
                return Optional.empty();
            }

            // Clean markdown code fence if Gemini wrapped it in ```json ... ```
            String cleanedJson = rawText.trim();
            if (cleanedJson.startsWith("```json")) {
                cleanedJson = cleanedJson.substring(7);
            } else if (cleanedJson.startsWith("```")) {
                cleanedJson = cleanedJson.substring(3);
            }
            if (cleanedJson.endsWith("```")) {
                cleanedJson = cleanedJson.substring(0, cleanedJson.length() - 3);
            }
            cleanedJson = cleanedJson.trim();

            GeminiAnalysisDto dto = objectMapper.readValue(cleanedJson, GeminiAnalysisDto.class);

            // Validation
            if (dto.getRiskLevel() == null ||
               (!dto.getRiskLevel().equalsIgnoreCase("LOW") &&
                !dto.getRiskLevel().equalsIgnoreCase("MEDIUM") &&
                !dto.getRiskLevel().equalsIgnoreCase("HIGH"))) {
                logger.warn("Gemini returned invalid risk level: {}", dto.getRiskLevel());
                return Optional.empty();
            }

            dto.setRiskLevel(dto.getRiskLevel().toUpperCase());

            if (dto.getConfidence() == null || dto.getConfidence() < 0.0 || dto.getConfidence() > 1.0) {
                dto.setConfidence(0.85);
            }

            if (dto.getScamType() == null || dto.getScamType().isBlank()) {
                dto.setScamType("Unclassified Threat");
            }

            return Optional.of(dto);
        } catch (Exception e) {
            logger.warn("Failed to parse Gemini response as JSON: {}. Response snippet: {}", e.getMessage(), responseJson);
            return Optional.empty();
        }
    }
}
