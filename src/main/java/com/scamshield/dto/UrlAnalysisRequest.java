package com.scamshield.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UrlAnalysisRequest {

    @NotBlank(message = "URL cannot be empty")
    @Size(max = 2048, message = "URL must not exceed 2048 characters")
    private String url;

    public UrlAnalysisRequest() {}

    public UrlAnalysisRequest(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
