package com.scamshield.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class MessageAnalysisRequest {

    @NotBlank(message = "Message content cannot be empty")
    @Size(max = 10000, message = "Message content must not exceed 10000 characters")
    private String message;

    public MessageAnalysisRequest() {}

    public MessageAnalysisRequest(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
