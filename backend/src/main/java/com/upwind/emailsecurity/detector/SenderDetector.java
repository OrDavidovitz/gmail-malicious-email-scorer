package com.upwind.emailsecurity.detector;

import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SenderDetector {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
            Pattern.CASE_INSENSITIVE
    );

    public List<RiskSignal> detect(EmailAnalysisRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        String from = safeLower(request.getFrom());
        String replyTo = safeLower(request.getReplyTo());

        String fromEmail = extractEmail(from);
        String replyToEmail = extractEmail(replyTo);

        String fromDomain = extractDomain(fromEmail);
        String replyToDomain = extractDomain(replyToEmail);

        if (!fromDomain.isEmpty()
                && !replyToDomain.isEmpty()
                && !fromDomain.equals(replyToDomain)) {
            signals.add(new RiskSignal(
                    "SENDER",
                    "MEDIUM",
                    "Reply-To domain is different from the sender domain.",
                    15
            ));
        }

        if (claimsKnownBrand(from) && usesFreeEmailProvider(fromDomain)) {
            signals.add(new RiskSignal(
                    "SENDER",
                    "HIGH",
                    "Sender claims to represent a known brand but uses a free email provider.",
                    25
            ));
        }

        if (containsLookalikeDomain(fromDomain)) {
            signals.add(new RiskSignal(
                    "SENDER",
                    "HIGH",
                    "Sender domain appears to imitate a known brand.",
                    25
            ));
        }

        if (containsAny(from, List.of("security", "support", "admin", "billing", "verification"))
                && fromDomain.isEmpty()) {
            signals.add(new RiskSignal(
                    "SENDER",
                    "LOW",
                    "Sender contains sensitive support/security wording but no valid email address was found.",
                    10
            ));
        }

        return signals;
    }

    private String extractEmail(String value) {
        Matcher matcher = EMAIL_PATTERN.matcher(value);

        if (matcher.find()) {
            return matcher.group();
        }

        return "";
    }

    private String extractDomain(String email) {
        int atIndex = email.indexOf('@');

        if (atIndex == -1 || atIndex == email.length() - 1) {
            return "";
        }

        return email.substring(atIndex + 1);
    }

    private boolean claimsKnownBrand(String text) {
        return containsAny(text, List.of(
                "paypal",
                "apple",
                "google",
                "microsoft",
                "amazon",
                "facebook",
                "meta",
                "netflix",
                "bank",
                "dhl",
                "fedex"
        ));
    }

    private boolean usesFreeEmailProvider(String domain) {
        return List.of(
                "gmail.com",
                "yahoo.com",
                "outlook.com",
                "hotmail.com",
                "icloud.com",
                "proton.me"
        ).contains(domain);
    }

    private boolean containsLookalikeDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }

        List<String> trustedBrands = List.of(
                "paypal",
                "google",
                "microsoft",
                "amazon",
                "apple",
                "netflix",
                "facebook",
                "meta"
        );

        String normalizedDomain = normalizeLookalikeText(domain);
        String domainCore = extractDomainCore(normalizedDomain);

        for (String brand : trustedBrands) {
            if (domainCore.equals(brand)) {
                return false;
            }

            if (domainCore.contains(brand)) {
                return true;
            }

            if (levenshteinDistance(domainCore, brand) == 1) {
                return true;
            }
        }

        return false;
    }

    private String normalizeLookalikeText(String text) {
        return text
                .replace("0", "o")
                .replace("1", "l")
                .replace("3", "e")
                .replace("5", "s")
                .replace("@", "a");
    }

    private String extractDomainCore(String domain) {
        int dotIndex = domain.indexOf('.');

        if (dotIndex == -1) {
            return domain;
        }

        return domain.substring(0, dotIndex);
    }

    private int levenshteinDistance(String first, String second) {
        int[][] dp = new int[first.length() + 1][second.length() + 1];

        for (int i = 0; i <= first.length(); i++) {
            dp[i][0] = i;
        }

        for (int j = 0; j <= second.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= first.length(); i++) {
            for (int j = 1; j <= second.length(); j++) {
                int cost = first.charAt(i - 1) == second.charAt(j - 1) ? 0 : 1;

                dp[i][j] = Math.min(
                        Math.min(
                                dp[i - 1][j] + 1,
                                dp[i][j - 1] + 1
                        ),
                        dp[i - 1][j - 1] + cost
                );
            }
        }

        return dp[first.length()][second.length()];
    }

    private boolean containsAny(String text, List<String> indicators) {
        for (String indicator : indicators) {
            if (text.contains(indicator.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    private String safeLower(String value) {
        if (value == null) {
            return "";
        }

        return value.toLowerCase();
    }
}