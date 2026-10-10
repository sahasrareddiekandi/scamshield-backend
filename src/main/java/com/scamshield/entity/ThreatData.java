package com.scamshield.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_data")
public class ThreatData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String indicatorType;

    @Column(nullable = false, length = 255)
    private String pattern;

    @Column(nullable = false, length = 80)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RiskLevel severity;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    private long detectionCount = 0;

    private LocalDateTime lastDetectedAt;

    public ThreatData() {
    }

    public ThreatData(String indicatorType, String pattern, String category, RiskLevel severity, String description) {
        this.indicatorType = indicatorType;
        this.pattern = pattern;
        this.category = category;
        this.severity = severity;
        this.description = description;
        this.detectionCount = 1;
        this.lastDetectedAt = LocalDateTime.now();
    }

    public void incrementDetections() {
        this.detectionCount++;
        this.lastDetectedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(String indicatorType) {
        this.indicatorType = indicatorType;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public RiskLevel getSeverity() {
        return severity;
    }

    public void setSeverity(RiskLevel severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public long getDetectionCount() {
        return detectionCount;
    }

    public void setDetectionCount(long detectionCount) {
        this.detectionCount = detectionCount;
    }

    public LocalDateTime getLastDetectedAt() {
        return lastDetectedAt;
    }

    public void setLastDetectedAt(LocalDateTime lastDetectedAt) {
        this.lastDetectedAt = lastDetectedAt;
    }
}
