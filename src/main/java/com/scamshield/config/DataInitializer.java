package com.scamshield.config;

import com.scamshield.entity.*;
import com.scamshield.repository.AnalysisRepository;
import com.scamshield.repository.ReportedContentRepository;
import com.scamshield.repository.ThreatDataRepository;
import com.scamshield.repository.UserRepository;
import com.scamshield.util.HashUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final AnalysisRepository analysisRepository;
    private final ReportedContentRepository reportedContentRepository;
    private final ThreatDataRepository threatDataRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository,
                           AnalysisRepository analysisRepository,
                           ReportedContentRepository reportedContentRepository,
                           ThreatDataRepository threatDataRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.analysisRepository = analysisRepository;
        this.reportedContentRepository = reportedContentRepository;
        this.threatDataRepository = threatDataRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        seedUsers();
        seedThreatData();
        seedSampleAnalyses();
        seedSampleReports();
        logger.info("ScamShield database seed check completed.");
    }

    private void seedUsers() {
        if (!userRepository.existsByEmail("admin@scamshield.io")) {
            User admin = new User();
            admin.setEmail("admin@scamshield.io");
            admin.setFullName("Security Administrator");
            admin.setPassword(passwordEncoder.encode("Admin@123"));
            admin.setRole(Role.ROLE_ADMIN);
            admin.setEnabled(true);
            userRepository.save(admin);
            logger.info("Seeded default administrator: admin@scamshield.io / Admin@123");
        }

        if (!userRepository.existsByEmail("user@scamshield.io")) {
            User demoUser = new User();
            demoUser.setEmail("user@scamshield.io");
            demoUser.setFullName("Cyber Analyst User");
            demoUser.setPassword(passwordEncoder.encode("User@123"));
            demoUser.setRole(Role.ROLE_USER);
            demoUser.setEnabled(true);
            userRepository.save(demoUser);
            logger.info("Seeded default standard user: user@scamshield.io / User@123");
        }
    }

    private void seedThreatData() {
        if (threatDataRepository.count() == 0) {
            threatDataRepository.saveAll(List.of(
                    new ThreatData("PATTERN", "URGENCY_LANGUAGE", "Social Engineering", RiskLevel.HIGH, "Threatening deadlines and high-pressure phrasing"),
                    new ThreatData("PATTERN", "PAYMENT_REQUEST", "Financial Fraud", RiskLevel.HIGH, "Demands for gift cards, crypto deposits, or wire transfers"),
                    new ThreatData("PATTERN", "CREDENTIAL_HARVESTING", "Credential Theft", RiskLevel.HIGH, "Solicitation of passwords, 2FA OTP codes, or SSN"),
                    new ThreatData("PATTERN", "AUTHORITY_IMPERSONATION", "Impersonation", RiskLevel.HIGH, "Fake IRS, FBI, or banking executive claims"),
                    new ThreatData("PATTERN", "PRIZE_LOTTERY_SCAM", "Advance-Fee", RiskLevel.HIGH, "Unsolicited lottery wins and fake reward claims"),
                    new ThreatData("PATTERN", "URL_HOST", "Infrastructure", RiskLevel.HIGH, "Direct IP address used as web host"),
                    new ThreatData("PATTERN", "URL_OBFUSCATION", "Deception", RiskLevel.HIGH, "At-sign character or punycode domain spoofing")
            ));
        }
    }

    private void seedSampleAnalyses() {
        if (analysisRepository.count() == 0) {
            User demoUser = userRepository.findByEmail("user@scamshield.io").orElse(null);

            // Sample 1: High risk bank phishing
            String msg1 = "URGENT: Your Chase Bank debit card has been suspended due to suspicious activity. Verify immediately at http://192.168.1.10/verify-account or your card will be permanently blocked within 24 hours.";
            Analysis a1 = new Analysis();
            a1.setUser(demoUser);
            a1.setContent(msg1);
            a1.setContentType(ContentType.MESSAGE);
            a1.setContentHash(HashUtils.sha256(msg1));
            a1.setRiskLevel(RiskLevel.HIGH);
            a1.setRiskScore(92);
            a1.setConfidence(0.96);
            a1.setScamType("Banking Credential Phishing");
            a1.setSummary("High Risk Alert (92/100): Aggressive banking credential harvesting attempt employing urgency threats and an unencrypted direct-IP phishing endpoint.");
            a1.setGeminiUsed(false);
            a1.setSafetyAdvice(List.of(
                    "Do NOT click the provided link or navigate to the IP address.",
                    "Never enter banking credentials, PINs, or card details on unverified pages.",
                    "Contact Chase Bank directly through the official phone number printed on the back of your card."
            ));
            a1.setSocialEngineeringTechniques(List.of(
                    "Manufactured Urgency: 24-hour ultimatum designed to bypass caution.",
                    "Authority Impersonation: Posing as a financial security fraud alert."
            ));
            a1.addIndicator(new AnalysisIndicator("URGENCY_LANGUAGE", "Urgent ultimatum threatening permanent card suspension within 24 hours", RiskLevel.HIGH, 25));
            a1.addIndicator(new AnalysisIndicator("ACCOUNT_SECURITY_BAIT", "False card suspension alarm mimicking Chase Bank", RiskLevel.MEDIUM, 20));
            a1.addIndicator(new AnalysisIndicator("URL_HOST", "Direct IP address host used in external link instead of legitimate domain", RiskLevel.HIGH, 35));
            analysisRepository.save(a1);

            // Sample 2: Suspicious URL
            String url1 = "http://paypal-security-account-update.xyz/login/verify?token=928471";
            Analysis a2 = new Analysis();
            a2.setUser(demoUser);
            a2.setContent(url1);
            a2.setContentType(ContentType.URL);
            a2.setContentHash(HashUtils.sha256(url1));
            a2.setRiskLevel(RiskLevel.HIGH);
            a2.setRiskScore(88);
            a2.setConfidence(0.94);
            a2.setScamType("Brand Spoofing & Credential Theft");
            a2.setSummary("High Risk Alert (88/100): Potential brand spoofing targeting PayPal on a high-risk .xyz disposable TLD with plain HTTP protocol.");
            a2.setGeminiUsed(false);
            a2.setSafetyAdvice(List.of(
                    "Do not enter any login credentials or personal passwords on this page.",
                    "Inspect your browser address bar: legitimate PayPal services only operate on paypal.com."
            ));
            a2.setSocialEngineeringTechniques(List.of(
                    "Domain Impersonation: Mimicking PayPal brand keywords with hyphens.",
                    "Credential Phishing: Target destination points to a fake login portal."
            ));
            a2.addIndicator(new AnalysisIndicator("BRAND_IMPERSONATION", "Domain contains 'paypal' but root domain is unregistered third-party .xyz", RiskLevel.HIGH, 35));
            a2.addIndicator(new AnalysisIndicator("URL_DOMAIN", "Disposable high-abuse TLD (.xyz)", RiskLevel.HIGH, 25));
            a2.addIndicator(new AnalysisIndicator("URL_PROTOCOL", "Insecure HTTP connection", RiskLevel.MEDIUM, 15));
            analysisRepository.save(a2);

            // Sample 3: Safe message
            String safeMsg = "Hi Alex, let's meet tomorrow at 10 AM in the conference room for the quarterly sprint review.";
            Analysis a3 = new Analysis();
            a3.setUser(demoUser);
            a3.setContent(safeMsg);
            a3.setContentType(ContentType.MESSAGE);
            a3.setContentHash(HashUtils.sha256(safeMsg));
            a3.setRiskLevel(RiskLevel.LOW);
            a3.setRiskScore(5);
            a3.setConfidence(0.98);
            a3.setScamType("Clean / Standard Communication");
            a3.setSummary("Low Risk (5/100): Standard conversational text. No phishing, credential harvesting, or extortion triggers detected.");
            a3.setGeminiUsed(false);
            a3.setSafetyAdvice(List.of(
                    "Standard workplace conversation. No threat mitigation necessary."
            ));
            a3.setSocialEngineeringTechniques(List.of(
                    "None detected."
            ));
            analysisRepository.save(a3);
        }
    }

    private void seedSampleReports() {
        if (reportedContentRepository.count() == 0) {
            User demoUser = userRepository.findByEmail("user@scamshield.io").orElse(null);

            ReportedContent r1 = new ReportedContent();
            r1.setUser(demoUser);
            r1.setContent("Your parcel delivery is pending! Pay $2.99 custom tax at http://fedex-customs-clearance.top/track");
            r1.setContentType(ContentType.MESSAGE);
            r1.setScamType("Courier Impersonation");
            r1.setDescription("Received via SMS pretending to be FedEx demanding payment for an undelivered parcel.");
            r1.setStatus(ReportStatus.PENDING);
            reportedContentRepository.save(r1);

            ReportedContent r2 = new ReportedContent();
            r2.setUser(demoUser);
            r2.setContent("http://amazon-giftcard-redeem.buzz/win");
            r2.setContentType(ContentType.URL);
            r2.setScamType("Fake Gift Card Generator");
            r2.setDescription("Site promises $500 Amazon gift cards after entering credit card information.");
            r2.setStatus(ReportStatus.VERIFIED_THREAT);
            r2.setAdminNotes("Confirmed credential and card harvesting phishing clone. Blocklisted.");
            reportedContentRepository.save(r2);
        }
    }
}
