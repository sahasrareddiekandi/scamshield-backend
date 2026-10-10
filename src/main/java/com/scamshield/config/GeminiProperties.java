package com.scamshield.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GeminiProperties {

    @Value("${scamshield.gemini.api-key:}")
    private String apiKey;

    @Value("${scamshield.gemini.model:gemini-1.5-flash}")
    private String model;

    @Value("${scamshield.gemini.api-url:https://generativelanguage.googleapis.com/v1beta/models}")
    private String apiUrl;

    @Value("${scamshield.gemini.timeout-ms:8000}")
    private int timeoutMs;

    public String getApiKey() {
        return apiKey;
    }

    public String getModel() {
        return model;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public boolean isConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }
}
