package com.scamshield.service;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.scamshield.dto.UrlDetailsDto;
import com.scamshield.entity.AnalysisIndicator;
import com.scamshield.entity.RiskLevel;

@Service
public class UrlAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(UrlAnalysisService.class);

    private static final Set<String> HIGH_RISK_TLDS = Set.of(
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
            "work", "fit", "surf", "click", "rest", "country", "stream",
            "cam", "monster", "bar", "live", "icu", "loan", "win"
    );

    private static final Set<String> TRUSTED_DOMAINS = Set.of(
            "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
            "wikipedia.org", "youtube.com", "linkedin.com", "gov", "edu", "mil"
    );

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
            "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "bc.vc"
    );

    private static final List<String> BRAND_KEYWORDS = List.of(
            "paypal", "amazon", "apple", "netflix", "microsoft", "google",
            "wellsfargo", "chase", "bankofamerica", "citibank", "binance",
            "coinbase", "metamask", "whatsapp", "telegram", "facebook", "instagram"
    );

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    public static class UrlAnalysisResult {
        private final UrlDetailsDto details;
        private final List<AnalysisIndicator> indicators;
        private final int calculatedScore;

        public UrlAnalysisResult(UrlDetailsDto details, List<AnalysisIndicator> indicators, int calculatedScore) {
            this.details = details;
            this.indicators = indicators;
            this.calculatedScore = calculatedScore;
        }

        public UrlDetailsDto getDetails() { return details; }
        public List<AnalysisIndicator> getIndicators() { return indicators; }
        public int getCalculatedScore() { return calculatedScore; }
    }

    public UrlAnalysisResult analyzeUrl(String rawUrl) {
        String normalized = normalizeUrl(rawUrl);
        UrlDetailsDto details = new UrlDetailsDto();
        details.setNormalizedUrl(normalized);

        List<AnalysisIndicator> indicators = new ArrayList<>();
        Set<String> detectedKeywordsSet = new LinkedHashSet<>();
        int score = 0;

        try {
            URI uri = URI.create(normalized);
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            int port = uri.getPort();
            String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";
            String query = uri.getQuery() != null ? uri.getQuery().toLowerCase() : "";

            details.setProtocol(scheme);
            details.setHost(host);
            details.setPort(port);
            details.setPath(path);
            details.setQuery(query);
            details.setHttps("https".equalsIgnoreCase(scheme));
            details.setUrlLength(normalized.length());

            boolean isIp = isIpAddress(host);
            details.setIpAddress(isIp);

            // Trusted domains with no spoofing/homograph/IP get a clean bill of health
            if (isTrustedDomain(host) && !isIp && !host.startsWith("xn--") && !host.contains("@")) {
                details.setDetectedKeywords(Collections.emptyList());
                details.setHasSuspiciousTld(false);
                details.setHasSpecialCharacters(false);
                details.setSubdomainCount(Math.max(0, host.split("\\.").length - 2));
                logger.info("URL_ANALYSIS: trusted domain '{}', finalScore=0, level=LOW", host);
                return new UrlAnalysisResult(details, Collections.emptyList(), 0);
            }

            List<String> hostTokens = extractTokens(host);
            List<String> pathTokens = extractTokens(path);
            List<String> queryTokens = extractTokens(query);
            List<String> pathQueryTokens = new ArrayList<>(pathTokens);
            pathQueryTokens.addAll(queryTokens);

            // 1. Insecure HTTP Protocol
            if (!details.isHttps()) {
                indicators.add(new AnalysisIndicator(
                        "URL_PROTOCOL",
                        "Potentially insecure connection: The URL uses unencrypted HTTP instead of HTTPS.",
                        RiskLevel.MEDIUM,
                        15
                ));
                score += 15;
            }

            // 2. IP Address host usage
            if (isIp) {
                indicators.add(new AnalysisIndicator(
                        "URL_HOST",
                        "Suspicious host structure: Host is a direct IP address rather than a verified domain name.",
                        RiskLevel.HIGH,
                        35
                ));
                score += 35;
            }

            // 3. High-abuse / Unusual TLD
            String tld = extractTld(host);
            if (tld != null && HIGH_RISK_TLDS.contains(tld)) {
                details.setHasSuspiciousTld(true);
                indicators.add(new AnalysisIndicator(
                        "URL_DOMAIN",
                        "Potentially suspicious Top-Level Domain (." + tld + ") frequently associated with disposable scam hosting.",
                        RiskLevel.HIGH,
                        25
                ));
                score += 25;
            }

            // 4. URL Shortener detection
            boolean isShortener = isShortenerDomain(host);
            if (isShortener) {
                indicators.add(new AnalysisIndicator(
                        "SHORTENED_URL",
                        "URL shortener domain (" + host + ") concealing the true destination target.",
                        RiskLevel.MEDIUM,
                        20
                ));
                score += 20;
            }

            // 5. Userinfo / @ symbol in URL
            if (normalized.contains("@")) {
                details.setHasSpecialCharacters(true);
                indicators.add(new AnalysisIndicator(
                        "URL_OBFUSCATION",
                        "Severe credential/destination spoofing attempt: Contains '@' character used to conceal real destination.",
                        RiskLevel.HIGH,
                        30
                ));
                score += 30;
            }

            // 6. Punycode / IDN Homograph
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                indicators.add(new AnalysisIndicator(
                        "URL_OBFUSCATION",
                        "Punycode (IDN) detected: May indicate a homograph spoofing attack mimicking legitimate letters.",
                        RiskLevel.HIGH,
                        25
                ));
                score += 25;
            }

            // 7. Subdomain depth and suspicious dashes
            String[] domainParts = host.split("\\.");
            int subdomainCount = Math.max(0, domainParts.length - 2);
            details.setSubdomainCount(subdomainCount);
            if (subdomainCount >= 3) {
                indicators.add(new AnalysisIndicator(
                        "URL_STRUCTURE",
                        "Excessive subdomain depth (" + subdomainCount + " levels) often engineered to deceive mobile browser address bars.",
                        RiskLevel.MEDIUM,
                        20
                ));
                score += 20;
            }

            long hyphenCount = host.chars().filter(ch -> ch == '-').count();
            if (hyphenCount >= 3) {
                details.setHasSpecialCharacters(true);
                indicators.add(new AnalysisIndicator(
                        "URL_STRUCTURE",
                        "Excessive hyphens in domain name (" + hyphenCount + " hyphens), a common pattern in machine-generated phishing domains.",
                        RiskLevel.MEDIUM,
                        15
                ));
                score += 15;
            } else if (hyphenCount >= 2) {
                details.setHasSpecialCharacters(true);
                indicators.add(new AnalysisIndicator(
                        "URL_STRUCTURE",
                        "Multiple hyphens in domain name (" + hyphenCount + " hyphens) frequently seen in deceptive hostnames.",
                        RiskLevel.MEDIUM,
                        10
                ));
                score += 10;
            }

            // 8. Brand Spoofing / Impersonation in Domain
            for (String brand : BRAND_KEYWORDS) {
                if (host.contains(brand) && !isLegitimateBrandDomain(host, brand)) {
                    detectedKeywordsSet.add(brand);
                    indicators.add(new AnalysisIndicator(
                            "BRAND_IMPERSONATION",
                            "Potential brand spoofing detected: Domain contains '" + brand + "' but is not hosted on the official root domain.",
                            RiskLevel.HIGH,
                            40
                    ));
                    score += 40;
                    break;
                }
            }

            // 9. Host Phishing / Credential Harvesting Analysis
            boolean hostHasBank = hostTokens.contains("bank") || hostTokens.contains("banking") || hostTokens.contains("netbanking");
            boolean hostHasLogin = hostTokens.contains("login") || hostTokens.contains("signin");
            boolean hostHasVerify = hostTokens.contains("verify") || hostTokens.contains("verification");
            boolean hostHasSecure = hostTokens.contains("secure") || hostTokens.contains("security");
            boolean hostHasOtp = hostTokens.contains("otp") || hostTokens.contains("password") || hostTokens.contains("pin");
            boolean hostHasSuspended = hostTokens.contains("suspended") || hostTokens.contains("suspend") || hostTokens.contains("blocked") || hostTokens.contains("locked");
            boolean hostHasAccount = hostTokens.contains("account");

            if (hostHasBank) detectedKeywordsSet.add("bank");
            if (hostHasLogin) detectedKeywordsSet.add("login");
            if (hostHasVerify) detectedKeywordsSet.add("verify");
            if (hostHasSecure) detectedKeywordsSet.add("secure");
            if (hostHasOtp) detectedKeywordsSet.add("otp");
            if (hostHasSuspended) detectedKeywordsSet.add("suspended");
            if (hostHasAccount) detectedKeywordsSet.add("account");

            // Host Phishing Combinations
            if (hostHasBank && (hostHasLogin || hostHasVerify || hostHasSecure || hostHasAccount || hostHasOtp)) {
                indicators.add(new AnalysisIndicator(
                        "CREDENTIAL_HARVESTING_HOST",
                        "Deceptive hostname impersonating a banking verification and login portal: " + host,
                        RiskLevel.HIGH,
                        65
                ));
                score += 65;
            } else if (hostHasSuspended && (hostHasLogin || hostHasAccount || hostHasVerify)) {
                indicators.add(new AnalysisIndicator(
                        "ACCOUNT_SUSPENSION_BAIT_HOST",
                        "Deceptive hostname engineering false account suspension and login capture: " + host,
                        RiskLevel.HIGH,
                        65
                ));
                score += 65;
            } else if (hostHasOtp || (hostHasLogin && hostHasVerify)) {
                indicators.add(new AnalysisIndicator(
                        "CREDENTIAL_HARVESTING_HOST",
                        "Critical phishing and credential harvesting pattern detected in hostname: " + host,
                        RiskLevel.HIGH,
                        60
                ));
                score += 60;
            }

            // 10. Path / Query Analysis
            boolean pathHasOtp = pathQueryTokens.contains("otp") || pathQueryTokens.contains("password") || pathQueryTokens.contains("pin") || pathQueryTokens.contains("cvv");
            boolean pathHasBank = pathQueryTokens.contains("bank") || pathQueryTokens.contains("banking");
            boolean pathHasVerify = pathQueryTokens.contains("verify") || pathQueryTokens.contains("verification");
            boolean pathHasAccount = pathQueryTokens.contains("account");
            boolean pathHasLogin = pathQueryTokens.contains("login") || pathQueryTokens.contains("signin");
            boolean pathHasOffer = pathQueryTokens.contains("offer") || pathQueryTokens.contains("deals") || pathQueryTokens.contains("promo") || pathQueryTokens.contains("discount");
            boolean pathHasUpdate = pathQueryTokens.contains("update") || pathQueryTokens.contains("upgrade");
            boolean pathHasBilling = pathQueryTokens.contains("billing") || pathQueryTokens.contains("invoice") || pathQueryTokens.contains("refund");

            if (pathHasOtp) detectedKeywordsSet.add("otp");
            if (pathHasBank) detectedKeywordsSet.add("bank");
            if (pathHasVerify) detectedKeywordsSet.add("verify");
            if (pathHasAccount) detectedKeywordsSet.add("account");
            if (pathHasLogin) detectedKeywordsSet.add("login");
            if (pathHasOffer) detectedKeywordsSet.add("offer");
            if (pathHasUpdate) detectedKeywordsSet.add("update");
            if (pathHasBilling) detectedKeywordsSet.add("billing");

            // Shortened URL + sensitive credential keywords -> HIGH
            if (isShortener && (pathHasOtp || (pathHasBank && pathHasVerify))) {
                indicators.add(new AnalysisIndicator(
                        "CREDENTIAL_HARVESTING_URL",
                        "Severe credential harvesting parameters detected in shortened URL: OTP and banking verification.",
                        RiskLevel.HIGH,
                        50
                ));
                score += 50;
            } else if (pathHasOtp) {
                // Direct OTP/password query in URL -> HIGH
                indicators.add(new AnalysisIndicator(
                        "CREDENTIAL_HARVESTING_URL",
                        "Direct credential solicitation (OTP/password/PIN) detected in URL path or parameters.",
                        RiskLevel.HIGH,
                        55
                ));
                score += 55;
            } else if (pathHasBank && (pathHasLogin || pathHasVerify)) {
                indicators.add(new AnalysisIndicator(
                        "PHISHING_KEYWORDS",
                        "Banking login/verification keywords detected in URL path.",
                        RiskLevel.HIGH,
                        45
                ));
                score += 45;
            } else if (pathHasAccount && pathHasVerify) {
                // e.g. https://example.com/account/verify -> MEDIUM
                indicators.add(new AnalysisIndicator(
                        "SENSITIVE_ACCOUNT_PATH",
                        "Sensitive account verification path (/account/verify) hosted on an unverified domain.",
                        RiskLevel.MEDIUM,
                        45
                ));
                score += 45;
            } else if (pathHasOffer) {
                // e.g. https://example.com/offer -> MEDIUM
                indicators.add(new AnalysisIndicator(
                        "PROMOTIONAL_LANDING_PATH",
                        "Promotional offer landing page (/offer) hosted on an unverified domain.",
                        RiskLevel.MEDIUM,
                        42
                ));
                score += 42;
            } else if (pathHasUpdate) {
                // e.g. https://example.com/update -> MEDIUM
                indicators.add(new AnalysisIndicator(
                        "ACCOUNT_UPDATE_PATH",
                        "Account or system update directive (/update) hosted on an unverified domain.",
                        RiskLevel.MEDIUM,
                        42
                ));
                score += 42;
            } else if (pathHasBilling) {
                indicators.add(new AnalysisIndicator(
                        "PHISHING_KEYWORDS",
                        "Billing or financial directive keyword (/billing) hosted on an unverified domain.",
                        RiskLevel.MEDIUM,
                        42
                ));
                score += 42;
            } else if (pathHasLogin || pathHasVerify) {
                indicators.add(new AnalysisIndicator(
                        "PHISHING_KEYWORDS",
                        "Authentication keyword detected in URL path on an unverified domain.",
                        RiskLevel.MEDIUM,
                        40
                ));
                score += 40;
            }

            // 11. Excessive URL Length
            if (normalized.length() > 120) {
                indicators.add(new AnalysisIndicator(
                        "URL_LENGTH",
                        "Abnormally long URL length (" + normalized.length() + " chars), typical of obfuscated phishing redirects.",
                        RiskLevel.MEDIUM,
                        20
                ));
                score += 20;
            }

            details.setDetectedKeywords(new ArrayList<>(detectedKeywordsSet));

        } catch (Exception e) {
            logger.warn("Malformed URL during analysis: {}", rawUrl);
            indicators.add(new AnalysisIndicator(
                    "URL_MALFORMED",
                    "URL format is malformed or invalid, preventing standard DNS resolution.",
                    RiskLevel.HIGH,
                    70
            ));
            score += 70;
        }

        boolean hasHighIndicator = indicators.stream().anyMatch(i -> i.getSeverity() == RiskLevel.HIGH);
        int finalScore = Math.min(100, Math.max(0, score));

        // Requirement B: Strong HIGH-risk signals must not be downgraded
        if (hasHighIndicator) {
            finalScore = Math.max(70, finalScore);
        }

        RiskLevel calculatedLevel = (finalScore >= 70) ? RiskLevel.HIGH : (finalScore >= 40 ? RiskLevel.MEDIUM : RiskLevel.LOW);
        logger.info("URL_ANALYSIS: rawUrl='{}', rawScore={}, finalScore={}, riskLevel={}, indicatorsCount={}, indicators={}",
                rawUrl, score, finalScore, calculatedLevel, indicators.size(),
                indicators.stream().map(AnalysisIndicator::getCategory).toList());

        return new UrlAnalysisResult(details, indicators, finalScore);
    }

    public String normalizeUrl(String url) {
        if (url == null) return "";
        String trimmed = url.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            trimmed = "https://" + trimmed;
        }
        return trimmed;
    }

    private List<String> extractTokens(String text) {
        if (text == null || text.isBlank()) return Collections.emptyList();
        String[] parts = text.toLowerCase().split("[^a-z0-9]+");
        List<String> tokens = new ArrayList<>();
        for (String part : parts) {
            if (!part.isBlank()) {
                tokens.add(part);
            }
        }
        return tokens;
    }

    private boolean isIpAddress(String host) {
        if (host == null || host.isBlank()) return false;
        return IPV4_PATTERN.matcher(host).matches();
    }

    private String extractTld(String host) {
        if (host == null || !host.contains(".")) return null;
        int lastDot = host.lastIndexOf('.');
        return host.substring(lastDot + 1);
    }

    private boolean isShortenerDomain(String host) {
        if (host == null || host.isBlank()) return false;
        for (String shortener : SHORTENER_DOMAINS) {
            if (host.equals(shortener) || host.endsWith("." + shortener)) {
                return true;
            }
        }
        return false;
    }

    private boolean isLegitimateBrandDomain(String host, String brand) {
        return host.equals(brand + ".com") ||
               host.endsWith("." + brand + ".com") ||
               host.equals(brand + ".org") ||
               host.endsWith("." + brand + ".org");
    }

    private boolean isTrustedDomain(String host) {
        for (String trusted : TRUSTED_DOMAINS) {
            if (host.equals(trusted) || host.endsWith("." + trusted)) {
                return true;
            }
        }
        return false;
    }
}