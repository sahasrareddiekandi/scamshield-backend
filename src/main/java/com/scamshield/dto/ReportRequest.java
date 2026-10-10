package com.scamshield.dto;

import com.scamshield.entity.ContentType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class ReportRequest {

    @NotBlank(message = "Suspicious content is required")
    @Size(max = 10000, message = "Content length exceeded")
    private String content;

    @NotNull(message = "Content type is required")
    private ContentType contentType;

    @Size(max = 100, message = "Scam type exceeded length")
    private String scamType;

    @Size(max = 2000, message = "Description exceeded length")
    private String description;

    public ReportRequest() {}

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public ContentType getContentType() {
        return contentType;
    }

    public void setContentType(ContentType contentType) {
        this.contentType = contentType;
    }

    public String getScamType() {
        return scamType;
    }

    public void setScamType(String scamType) {
        this.scamType = scamType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
