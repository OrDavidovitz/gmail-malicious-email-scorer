package com.upwind.emailsecurity.service;

import com.upwind.emailsecurity.detector.AttachmentDetector;
import com.upwind.emailsecurity.detector.ContentDetector;
import com.upwind.emailsecurity.detector.LinkDetector;
import com.upwind.emailsecurity.detector.SenderDetector;
import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.EmailAnalysisResponse;
import com.upwind.emailsecurity.model.RiskSignal;
import com.upwind.emailsecurity.model.Verdict;
import org.springframework.stereotype.Service;
import com.upwind.emailsecurity.detector.AuthenticationDetector;

import java.util.ArrayList;
import java.util.List;

@Service
public class EmailAnalysisService {

    private final ScoringEngine scoringEngine;
    private final SenderDetector senderDetector;
    private final ContentDetector contentDetector;
    private final LinkDetector linkDetector;
    private final AttachmentDetector attachmentDetector;
    private final AuthenticationDetector authenticationDetector;

    public EmailAnalysisService(ScoringEngine scoringEngine,
                                SenderDetector senderDetector,
                                ContentDetector contentDetector,
                                LinkDetector linkDetector,
                                AttachmentDetector attachmentDetector,
                                AuthenticationDetector authenticationDetector) {
        this.scoringEngine = scoringEngine;
        this.senderDetector = senderDetector;
        this.contentDetector = contentDetector;
        this.linkDetector = linkDetector;
        this.attachmentDetector = attachmentDetector;
        this.authenticationDetector = authenticationDetector;
    }

    public EmailAnalysisResponse analyze(EmailAnalysisRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        signals.addAll(senderDetector.detect(request));
        signals.addAll(contentDetector.detect(request));
        signals.addAll(linkDetector.detect(request));
        signals.addAll(attachmentDetector.detect(request));
        signals.addAll(authenticationDetector.detect(request.getAuthenticationResults()));

        int score = scoringEngine.calculateScore(signals);
        Verdict verdict = scoringEngine.determineVerdict(score);

        return new EmailAnalysisResponse(
                score,
                verdict,
                buildSummary(verdict, signals),
                signals,
                buildRecommendedAction(verdict)
        );
    }

    private String buildSummary(Verdict verdict, List<RiskSignal> signals) {
        if (signals.isEmpty()) {
            return "This email does not show strong malicious indicators.";
        }

        if (verdict == Verdict.CRITICAL || verdict == Verdict.HIGH) {
            return "This email contains several suspicious indicators.";
        }

        if (verdict == Verdict.MEDIUM) {
            return "This email contains some suspicious indicators.";
        }

        return "This email contains minor suspicious indicators.";
    }

    private String buildRecommendedAction(Verdict verdict) {
        if (verdict == Verdict.CRITICAL || verdict == Verdict.HIGH) {
            return "Do not click links or download attachments. Verify the sender through another trusted channel.";
        }

        if (verdict == Verdict.MEDIUM) {
            return "Be careful before interacting with this email. Verify suspicious links or requests.";
        }

        return "No immediate action required, but remain cautious with unexpected emails.";
    }
}