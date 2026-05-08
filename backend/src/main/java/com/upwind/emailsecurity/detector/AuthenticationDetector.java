package com.upwind.emailsecurity.detector;

import com.upwind.emailsecurity.model.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Component
public class AuthenticationDetector {

    public List<RiskSignal> detect(String authenticationResults) {
        List<RiskSignal> signals = new ArrayList<>();

        if (authenticationResults == null || authenticationResults.isBlank()) {
            return signals;
        }

        String normalized = authenticationResults.toLowerCase(Locale.ROOT);

        if (containsFailure(normalized, "spf")) {
            signals.add(new RiskSignal(
                    "AUTHENTICATION",
                    "HIGH",
                    "Email authentication check failed for SPF.",
                    25
            ));
        }

        if (containsFailure(normalized, "dkim")) {
            signals.add(new RiskSignal(
                    "AUTHENTICATION",
                    "HIGH",
                    "Email authentication check failed for DKIM.",
                    25
            ));
        }

        if (containsFailure(normalized, "dmarc")) {
            signals.add(new RiskSignal(
                    "AUTHENTICATION",
                    "HIGH",
                    "Email authentication check failed for DMARC.",
                    30
            ));
        }

        if (containsSoftFailure(normalized, "spf")) {
            signals.add(new RiskSignal(
                    "AUTHENTICATION",
                    "MEDIUM",
                    "Email authentication check returned a soft failure for SPF.",
                    15
            ));
        }

        return signals;
    }

    private boolean containsFailure(String text, String mechanism) {
        return text.contains(mechanism + "=fail")
                || text.contains(mechanism + "=permerror")
                || text.contains(mechanism + "=temperror");
    }

    private boolean containsSoftFailure(String text, String mechanism) {
        return text.contains(mechanism + "=softfail")
                || text.contains(mechanism + "=neutral");
    }
}