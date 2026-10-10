package com.scamshield.entity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "analyses", indexes = {
    @Index(name = "idx_content_hash", columnList = "contentHash"),
    @Index(name = "idx_created_at", columnList = "createdAt")
})
public class Analysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ContentType contentType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RiskLevel riskLevel;

    @Column(nullable = false)
    private int riskScore;

    @Column(nullable = false)
    private double confidence;

    @Column(length = 100)
    private String scamType;

    @Column(columnDefinition = "TEXT")
    private String summary;

    @Column(nullable = false)
    private boolean geminiUsed;

    @Column(columnDefinition = "TEXT")
    private String geminiRawResponse;

    @Column(length = 64)
    private String contentHash;

    /*
     * EAGER loading is used here so that indicators are available
     * when Analysis is converted to AnalysisResponse.
     */
    @OneToMany(
        mappedBy = "analysis",
        cascade = CascadeType.ALL,
        orphanRemoval = true,
        fetch = FetchType.EAGER
    )
    private List<AnalysisIndicator> indicators = new ArrayList<>();

    /*
     * EAGER loading prevents LazyInitializationException when
     * safetyAdvice is accessed while creating the response DTO.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "analysis_safety_advice",
        joinColumns = @JoinColumn(name = "analysis_id")
    )
    @Column(name = "advice", length = 500)
    private List<String> safetyAdvice = new ArrayList<>();

    /*
     * EAGER loading prevents the same problem for
     * socialEngineeringTechniques.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "analysis_social_engineering",
        joinColumns = @JoinColumn(name = "analysis_id")
    )
    @Column(name = "technique", length = 500)
    private List<String> socialEngineeringTechniques = new ArrayList<>();

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;


    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    public Analysis() {
    }


    // ============================================================
    // PRE-PERSIST
    // ============================================================

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }


    // ============================================================
    // INDICATOR METHODS
    // ============================================================

    public void addIndicator(AnalysisIndicator indicator) {
        indicators.add(indicator);
        indicator.setAnalysis(this);
    }

    public void removeIndicator(AnalysisIndicator indicator) {
        indicators.remove(indicator);
        indicator.setAnalysis(null);
    }


    // ============================================================
    // GETTERS AND SETTERS
    // ============================================================

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }


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


    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }


    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }


    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }


    public String getScamType() {
        return scamType;
    }

    public void setScamType(String scamType) {
        this.scamType = scamType;
    }


    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }


    public boolean isGeminiUsed() {
        return geminiUsed;
    }

    public void setGeminiUsed(boolean geminiUsed) {
        this.geminiUsed = geminiUsed;
    }


    public String getGeminiRawResponse() {
        return geminiRawResponse;
    }

    public void setGeminiRawResponse(String geminiRawResponse) {
        this.geminiRawResponse = geminiRawResponse;
    }


    public String getContentHash() {
        return contentHash;
    }

    public void setContentHash(String contentHash) {
        this.contentHash = contentHash;
    }


    public List<AnalysisIndicator> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<AnalysisIndicator> indicators) {
        this.indicators = indicators;
    }


    public List<String> getSafetyAdvice() {
        return safetyAdvice;
    }

    public void setSafetyAdvice(List<String> safetyAdvice) {
        this.safetyAdvice = safetyAdvice;
    }


    public List<String> getSocialEngineeringTechniques() {
        return socialEngineeringTechniques;
    }

    public void setSocialEngineeringTechniques(List<String> socialEngineeringTechniques) {
        this.socialEngineeringTechniques = socialEngineeringTechniques;
    }


    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}




