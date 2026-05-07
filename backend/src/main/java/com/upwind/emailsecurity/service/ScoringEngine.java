package com.upwind.emailsecurity.service;

import com.upwind.emailsecurity.model.RiskSignal;
import com.upwind.emailsecurity.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ScoringEngine {

    public int calculateScore(List<RiskSignal> signals) {
        int total = 0;

        for (RiskSignal signal : signals) {
            total += signal.getPoints();
        }

        return Math.min(total, 100);
    }

    public Verdict determineVerdict(int score) {
        if (score >= 85) {
            return Verdict.CRITICAL;
        }

        if (score >= 60) {
            return Verdict.HIGH;
        }

        if (score >= 30) {
            return Verdict.MEDIUM;
        }

        return Verdict.LOW;
    }
}