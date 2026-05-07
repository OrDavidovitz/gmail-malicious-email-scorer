package com.upwind.emailsecurity.detector;

import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class ContentDetector {

    public List<RiskSignal> detect(EmailAnalysisRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        String subject = safeLower(request.getSubject());
        String body = safeLower(request.getBody());
        String content = subject + " " + body;

        if (containsAny(content, List.of("urgent", "immediately", "act now", "final warning"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "MEDIUM",
                    "Email uses urgent or pressure-based language.",
                    15
            ));
        }

        if (containsAny(content, List.of("verify your account", "confirm your account", "account suspended", "account will be suspended"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "HIGH",
                    "Email contains account-verification or suspension language commonly used in phishing.",
                    20
            ));
        }

        if (containsAny(content, List.of("password", "login", "credentials", "sign in", "2fa", "two-factor"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "HIGH",
                    "Email asks about login, password, or credential-related actions.",
                    20
            ));
        }

        if (containsAny(content, List.of("payment failed", "billing issue", "invoice overdue", "update payment", "wire transfer"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "MEDIUM",
                    "Email contains financial pressure or payment-related language.",
                    15
            ));
        }
        if (containsAny(content, List.of("you won", "winner", "claim your prize", "gift card", "lottery", "reward", "congratulations"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "MEDIUM",
                    "Email contains prize, reward, or lottery language commonly used in scams.",
                    15
            ));
        }

        if (containsAny(content, List.of("tax refund", "refund available", "government refund", "irs", "tax authority", "claim your refund"))) {
            signals.add(new RiskSignal(
                    "CONTENT",
                    "MEDIUM",
                    "Email contains refund or tax-related language that may be used for impersonation scams.",
                    15
            ));
        }

        return signals;
    }

    private String safeLower(String value) {
        if (value == null) {
            return "";
        }

        return value.toLowerCase();
    }

    private boolean containsAny(String text, List<String> indicators) {
        for (String indicator : indicators) {
            if (text.contains(indicator)) {
                return true;
            }
        }

        return false;
    }
}