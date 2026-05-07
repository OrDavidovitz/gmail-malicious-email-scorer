package com.upwind.emailsecurity.model;

import java.util.List;

public class EmailAnalysisResponse {

    private int score;
    private Verdict verdict;
    private String summary;
    private List<RiskSignal> signals;
    private String recommendedAction;

    public EmailAnalysisResponse() {
    }

    public EmailAnalysisResponse(int score, Verdict verdict, String summary,
                                 List<RiskSignal> signals, String recommendedAction) {
        this.score = score;
        this.verdict = verdict;
        this.summary = summary;
        this.signals = signals;
        this.recommendedAction = recommendedAction;
    }

    public int getScore() {
        return score;
    }

    public Verdict getVerdict() {
        return verdict;
    }

    public String getSummary() {
        return summary;
    }

    public List<RiskSignal> getSignals() {
        return signals;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public void setVerdict(Verdict verdict) {
        this.verdict = verdict;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public void setSignals(List<RiskSignal> signals) {
        this.signals = signals;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }
}