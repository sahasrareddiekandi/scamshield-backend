package com.scamshield.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.RiskLevel;
import com.scamshield.util.UrlExtractor;

@Service
public class MessageAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(MessageAnalysisService.class);
    private final UrlAnalysisService urlAnalysisService;

    public MessageAnalysisService(UrlAnalysisService urlAnalysisService) {
        this.urlAnalysisService = urlAnalysisService;
    }

    public static class MessageAnalysisResult {
        private final List<AnalysisIndicator> indicators;
        private final List<String> extractedUrls;
        private final int calculatedScore;
        private final String primaryScamCategory;

        public MessageAnalysisResult(List<AnalysisIndicator> indicators, List<String> extractedUrls, int calculatedScore, String primaryScamCategory) {
            this.indicators = indicators;
            this.extractedUrls = extractedUrls;
            this.calculatedScore = calculatedScore;
            this.primaryScamCategory = primaryScamCategory;
        }

        public List<AnalysisIndicator> getIndicators() { return indicators; }
        public List<String> getExtractedUrls() { return extractedUrls; }
        public int getCalculatedScore() { return calculatedScore; }
        public String getPrimaryScamCategory() { return primaryScamCategory; }
    }

    // High-Risk Pattern Definitions
    private static final Pattern URGENCY_PATTERN = Pattern.compile(
            "\\b(immediate(ly)?|urgent(ly)?|act now|within (24|12|48) hours|final notice|time[ -]sensitive|immediate action required|suspended indefinitely|warrant|arrest|legal action|asap|blocked today)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PAYMENT_PATTERN = Pattern.compile(
            "\\b(gift card|crypto|bitcoin|btc|eth|usdt|wire transfer|western union|moneygram|zelle|cashapp|cash app|send money|advance fee|processing fee|deposit required|unpaid invoice|pay now|pay [₹$€£]?[0-9,]+|transfer [₹$€£]?[0-9,]+)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
            "\\b(otp|one[ -]time password|passcode|6[ -]digit code|pin number|banking password|share your password|enter your (banking )?password|enter your (otp|pin)|verify your credentials|ssn|social security|cvv|card number|bank account number|login credentials|seed phrase|private key)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile(
            "\\b(fbi|irs|internal revenue|interpol|department of justice|police department|customs|cyber crime|fraud prevention|central bank|federal reserve|tax department|tax refund department)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern LOTTERY_PRIZE_PATTERN = Pattern.compile(
            "\\b(congratulations!?( you (have )?won)?|lottery winner|claim your prize|selected as the winner|cash prize|jackpot|inheritance fund|beneficiary of|free reward|won a [₹$€£]?[0-9,]+ prize|guaranteed (500%|1000%|daily) return)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ACCOUNT_SUSPENSION_PATTERN = Pattern.compile(
            "\\b((bank )?account (will be |has been |is )?blocked|account (suspended|locked|deactivated|frozen|terminated|restricted)|card blocked|service cancellation|temporary hold|unauthorized (login|transaction|access)|suspicious activity detected|kyc (has )?expired|kyc expiring|update (your )?kyc|complete (your )?kyc|verify (your )?kyc)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SOCIAL_ENGINEERING_PATTERN = Pattern.compile(
            "\\b(keep this confidential|do not tell anyone|stranded abroad|emergency assistance|secret mission|work from home \\$[0-9]+|earn \\$[0-9]+ per day|high return investment)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Medium-Risk Pattern Definitions
    private static final Pattern ACCOUNT_VERIFICATION_PATTERN = Pattern.compile(
            "\\b(account needs verification|review your account (details)?|verify your account details|update your account details|verify your identity|confirm your account details|check your account)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PROMOTIONAL_LURE_PATTERN = Pattern.compile(
            "\\b(limited[- ]time offer|special offer|exclusive offer|exclusive deal|discount coupon|promotional offer|special discount|claim your discount|limited time deal)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SUBSCRIPTION_BILLING_PATTERN = Pattern.compile(
            "\\b(subscription (is )?expiring|subscription renewed|review your payment details|update your payment (method|details)|membership expiring|billing notice|payment method expiring)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern CALL_TO_ACTION_LINKS = Pattern.compile(
            "\\b(using this link|click (here|the link|below)|tap (here|the link)|follow (this|the) link|visit (this|the) link|open the link|login here to verify|secure link|click the link to learn more|link to learn more)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern MODERATE_URGENCY_PATTERN = Pattern.compile(
            "\\b(expiring soon|expires soon|needs verification soon|act soon|ending soon|due soon|verify soon|reply soon|respond soon|closing soon|action required soon|limited[- ]time)\\b",
            Pattern.CASE_INSENSITIVE
    );

    public MessageAnalysisResult analyzeMessage(String message) {
        List<AnalysisIndicator> indicators = new ArrayList<>();
        int score = 0;
        Map<String, Integer> categoryPoints = new HashMap<>();

        if (message == null || message.isBlank()) {
            return new MessageAnalysisResult(indicators, Collections.emptyList(), 0, "Clean / Low Risk");
        }

        boolean urgencyMatched = false;

        // 1. Urgency & Threats
        if (URGENCY_PATTERN.matcher(message).find()) {
            urgencyMatched = true;
            indicators.add(new AnalysisIndicator(
                    "URGENCY_LANGUAGE",
                    "Artificial urgency or threatening tone detected, pressuring recipient into hasty decision-making.",
                    RiskLevel.HIGH,
                    25
            ));
            score += 25;
            categoryPoints.merge("Urgency / Pressure", 25, Integer::sum);
        }

        // 2. Financial / Payment Requests
        boolean paymentMatched = false;
        if (PAYMENT_PATTERN.matcher(message).find()) {
            paymentMatched = true;
            indicators.add(new AnalysisIndicator(
                    "PAYMENT_REQUEST",
                    "Request for untraceable or advance fees / payment methods (cryptocurrency, gift cards, wire transfer, processing fee).",
                    RiskLevel.HIGH,
                    30
            ));
            score += 30;
            categoryPoints.merge("Financial Extortion / Payment", 30, Integer::sum);
        }

        // 3. Credential Harvesting / Sensitive Data
        boolean credentialMatched = false;
        if (CREDENTIAL_PATTERN.matcher(message).find()) {
            credentialMatched = true;
            indicators.add(new AnalysisIndicator(
                    "CREDENTIAL_HARVESTING",
                    "Solicitation of sensitive security credentials (OTP, banking passwords, PINs, SSN, or private keys).",
                    RiskLevel.HIGH,
                    35
            ));
            score += 35;
            categoryPoints.merge("Credential Harvesting", 35, Integer::sum);
        }

        // 4. Authority Impersonation
        if (AUTHORITY_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "AUTHORITY_IMPERSONATION",
                    "Claim of official law enforcement, tax agency, or government authority to intimidate the victim.",
                    RiskLevel.HIGH,
                    30
            ));
            score += 30;
            categoryPoints.merge("Authority Impersonation", 30, Integer::sum);
        }

        // 5. Prize / Lottery / Unsolicited Funds
        boolean prizeMatched = false;
        if (LOTTERY_PRIZE_PATTERN.matcher(message).find()) {
            prizeMatched = true;
            indicators.add(new AnalysisIndicator(
                    "PRIZE_LOTTERY_SCAM",
                    "Unsolicited prize, lottery winning, or high-return investment bait without prior interaction.",
                    RiskLevel.HIGH,
                    30
            ));
            score += 30;
            categoryPoints.merge("Prize / Advance-Fee Scam", 30, Integer::sum);
        }

        // 6. Account Suspension / Blocking Warnings & Fake KYC
        boolean suspensionMatched = false;
        if (ACCOUNT_SUSPENSION_PATTERN.matcher(message).find()) {
            suspensionMatched = true;
            indicators.add(new AnalysisIndicator(
                    "ACCOUNT_SECURITY_BAIT",
                    "False account security alarm, KYC expiration, or suspension threat designed to trigger panic login behavior.",
                    RiskLevel.HIGH,
                    30
            ));
            score += 30;
            categoryPoints.merge("Account Impersonation", 30, Integer::sum);
        }

        // 7. Social Engineering Patterns
        if (SOCIAL_ENGINEERING_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "SOCIAL_ENGINEERING",
                    "Psychological manipulation patterns identified (secrecy demand, fake crisis, or unrealistic income bait).",
                    RiskLevel.HIGH,
                    25
            ));
            score += 25;
            categoryPoints.merge("Social Engineering", 25, Integer::sum);
        }

        // 8. Account Review / Verification Reminders (Moderate)
        if (!suspensionMatched && ACCOUNT_VERIFICATION_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "ACCOUNT_VERIFICATION_NOTICE",
                    "Routine account verification or review directive without overt suspension threats.",
                    RiskLevel.MEDIUM,
                    25
            ));
            score += 25;
            categoryPoints.merge("Account Review", 25, Integer::sum);
        }

        // 9. Promotional Lure (Moderate)
        if (!prizeMatched && PROMOTIONAL_LURE_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "PROMOTIONAL_LURE",
                    "Promotional offer or marketing incentive encouraging recipient engagement.",
                    RiskLevel.MEDIUM,
                    25
            ));
            score += 25;
            categoryPoints.merge("Promotional Message", 25, Integer::sum);
        }

        // 10. Subscription / Billing Review (Moderate)
        if (SUBSCRIPTION_BILLING_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "BILLING_SUBSCRIPTION_NOTICE",
                    "Subscription renewal or payment details review notification.",
                    RiskLevel.MEDIUM,
                    25
            ));
            score += 25;
            categoryPoints.merge("Billing Notice", 25, Integer::sum);
        }

        // 11. Moderate Urgency Language
        if (!urgencyMatched && MODERATE_URGENCY_PATTERN.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "MODERATE_URGENCY",
                    "Moderate time-sensitivity or upcoming expiration notice detected.",
                    RiskLevel.MEDIUM,
                    20
            ));
            score += 20;
            categoryPoints.merge("Urgency / Pressure", 20, Integer::sum);
        }

        // 12. Call-to-action Links
        if (CALL_TO_ACTION_LINKS.matcher(message).find()) {
            indicators.add(new AnalysisIndicator(
                    "CALL_TO_ACTION_LINK",
                    "Directive commanding user to click an external link, portal, or review link.",
                    RiskLevel.MEDIUM,
                    20
            ));
            score += 20;
            categoryPoints.merge("Phishing Lure", 20, Integer::sum);
        }

        // 13. Extract and analyze embedded URLs
        List<String> extractedUrls = UrlExtractor.extractUrls(message);
        boolean embeddedHighUrl = false;
        if (!extractedUrls.isEmpty()) {
            for (String url : extractedUrls) {
                UrlAnalysisService.UrlAnalysisResult urlResult = urlAnalysisService.analyzeUrl(url);
                if (urlResult.getCalculatedScore() >= 70) {
                    embeddedHighUrl = true;
                    indicators.add(new AnalysisIndicator(
                            "EMBEDDED_SUSPICIOUS_URL",
                            "Message embeds a high-risk malicious link (" + url + ") with risk score " + urlResult.getCalculatedScore() + "/100.",
                            RiskLevel.HIGH,
                            50
                    ));
                    score += 50;
                    categoryPoints.merge("Malicious Link Phishing", 50, Integer::sum);
                } else if (urlResult.getCalculatedScore() >= 40) {
                    indicators.add(new AnalysisIndicator(
                            "EMBEDDED_SUSPICIOUS_URL",
                            "Message embeds a suspicious link (" + url + ") with risk score " + urlResult.getCalculatedScore() + "/100.",
                            RiskLevel.MEDIUM,
                            25
                    ));
                    score += 25;
                    categoryPoints.merge("Suspicious Link Phishing", 25, Integer::sum);
                }
            }
        }

        // Requirement B: Strong HIGH-risk signals must not be downgraded
        boolean hasStrongHighSignal = credentialMatched ||
                embeddedHighUrl ||
                (suspensionMatched && (urgencyMatched || credentialMatched || !extractedUrls.isEmpty())) ||
                (prizeMatched && (paymentMatched || urgencyMatched)) ||
                (urgencyMatched && paymentMatched) ||
                (urgencyMatched && credentialMatched);

        int finalScore = Math.min(100, Math.max(0, score));
        if (hasStrongHighSignal || finalScore >= 70) {
            finalScore = Math.max(70, finalScore);
        }

        // Determine primary category
        String primaryCategory = categoryPoints.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("Legitimate / Unclassified");

        if (finalScore < 40) {
            primaryCategory = "Clean / Low Risk";
        }

        RiskLevel calculatedLevel = (finalScore >= 70) ? RiskLevel.HIGH : (finalScore >= 40 ? RiskLevel.MEDIUM : RiskLevel.LOW);
        logger.info("MESSAGE_ANALYSIS: rawScore={}, finalScore={}, riskLevel={}, primaryCategory={}, indicatorsCount={}, indicators={}",
                score, finalScore, calculatedLevel, primaryCategory, indicators.size(),
                indicators.stream().map(AnalysisIndicator::getCategory).toList());

        return new MessageAnalysisResult(indicators, extractedUrls, finalScore, primaryCategory);
    }
}