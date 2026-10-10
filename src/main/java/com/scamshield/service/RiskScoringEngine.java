package com.scamshield.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;

import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.RiskLevel;

@Service
public class RiskScoringEngine {

    public int normalizeScore(int score) {
        return Math.max(0, Math.min(100, score));
    }

    public RiskLevel determineRiskLevel(int score) {
        int clamped = normalizeScore(score);
        if (clamped < 40) {
            return RiskLevel.LOW;
        } else if (clamped < 70) {
            return RiskLevel.MEDIUM;
        } else {
            return RiskLevel.HIGH;
        }
    }

    public RiskLevel determineRiskLevel(int score, List<AnalysisIndicator> indicators) {
        if (indicators != null && indicators.stream().anyMatch(i -> i.getSeverity() == RiskLevel.HIGH)) {
            return RiskLevel.HIGH;
        }
        return determineRiskLevel(score);
    }

    public double calculateConfidence(int score, List<AnalysisIndicator> indicators) {
        if (indicators == null || indicators.isEmpty()) {
            return score == 0 ? 0.95 : 0.70;
        }
        double base = 0.75;
        base += Math.min(0.20, indicators.size() * 0.04);
        boolean hasHighSeverity = indicators.stream().anyMatch(i -> i.getSeverity() == RiskLevel.HIGH);
        if (hasHighSeverity) {
            base += 0.04;
        }
        return Math.min(0.99, Math.round(base * 100.0) / 100.0);
    }

    public List<String> generateSafetyAdvice(RiskLevel riskLevel, List<AnalysisIndicator> indicators) {
        Set<String> adviceSet = new LinkedHashSet<>();

        boolean hasCredentials = indicators != null && indicators.stream().anyMatch(i -> i.getCategory().contains("CREDENTIAL"));
        boolean hasPayment = indicators != null && indicators.stream().anyMatch(i -> i.getCategory().contains("PAYMENT"));
        boolean hasUrl = indicators != null && indicators.stream().anyMatch(i -> i.getCategory().contains("URL") || i.getCategory().contains("PHISHING"));
        boolean hasUrgency = indicators != null && indicators.stream().anyMatch(i -> i.getCategory().contains("URGENCY"));
        boolean hasAuthority = indicators != null && indicators.stream().anyMatch(i -> i.getCategory().contains("AUTHORITY"));

        if (riskLevel == RiskLevel.HIGH) {
            adviceSet.add("Do NOT click any links or download any files attached to this message.");
            adviceSet.add("Never share OTPs, passwords, PIN numbers, or credit card CVVs with anyone.");
            if (hasPayment) {
                adviceSet.add("Do NOT send money, cryptocurrency, wire transfers, or gift card codes.");
            }
            if (hasAuthority) {
                adviceSet.add("Government agencies and banks will never contact you via text/email demanding immediate payment.");
            }
            adviceSet.add("Block the sender and report this message immediately to your IT security team or local cyber cell.");
        } else if (riskLevel == RiskLevel.MEDIUM) {
            adviceSet.add("Exercise caution. Verify the sender's identity through an official and verified phone number.");
            if (hasUrl) {
                adviceSet.add("Do not enter login credentials or personal data if you decide to visit this website.");
                adviceSet.add("Check the browser address bar to ensure the root domain precisely matches the real service.");
            }
            if (hasUrgency) {
                adviceSet.add("Pause before reacting. Scammers intentionally manufacture artificial deadlines to bypass rational thought.");
            }
            adviceSet.add("If this claims to be from a service you use, navigate directly to their official app or website instead.");
        } else {
            adviceSet.add("Content does not exhibit classic phishing or scam signatures.");
            adviceSet.add("Always maintain cybersecurity awareness and inspect sender email domains.");
            adviceSet.add("Never input personal credentials on websites lacking HTTPS encryption.");
        }

        return new ArrayList<>(adviceSet);
    }

    public String generateSummary(RiskLevel riskLevel, int score, String scamType, List<AnalysisIndicator> indicators) {
        if (riskLevel == RiskLevel.HIGH) {
            int count = (indicators != null) ? indicators.size() : 0;
            return String.format("High Risk Alert (%d/100): Strong indicators of a %s detected. " +
                    "Identified %d threat indicators including severe risk patterns.", score, scamType, count);
        } else if (riskLevel == RiskLevel.MEDIUM) {
            return String.format("Medium Suspicion (%d/100): Potential risk patterns identified consistent with %s. " +
                    "Review flagged indicators before taking any action.", score, scamType);
        } else {
            return String.format("Low Risk (%d/100): No aggressive malicious patterns detected. Content appears standard.", score);
        }
    }
}