package com.upwind.emailsecurity.detector;

import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class LinkDetector {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[^\\s]+|www\\.[^\\s]+)",
            Pattern.CASE_INSENSITIVE
    );

    public List<RiskSignal> detect(EmailAnalysisRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        String body = safeLower(request.getBody());
        List<String> urls = extractUrls(body);

        if (urls.isEmpty()) {
            return signals;
        }

        if (urls.size() >= 3) {
            signals.add(new RiskSignal(
                    "LINK",
                    "MEDIUM",
                    "Email contains multiple links, which can increase phishing risk.",
                    10
            ));
        }

        if (containsShortenedUrl(urls)) {
            signals.add(new RiskSignal(
                    "LINK",
                    "HIGH",
                    "Email contains a shortened URL, which can hide the final destination.",
                    25
            ));
        }

        if (containsRawIpUrl(urls)) {
            signals.add(new RiskSignal(
                    "LINK",
                    "HIGH",
                    "Email contains a link that uses a raw IP address instead of a domain.",
                    25
            ));
        }

        if (containsSuspiciousTld(urls)) {
            signals.add(new RiskSignal(
                    "LINK",
                    "MEDIUM",
                    "Email contains a link with a suspicious or uncommon top-level domain.",
                    15
            ));
        }

        return signals;
    }

    private List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);

        while (matcher.find()) {
            urls.add(matcher.group());
        }

        return urls;
    }

    private boolean containsShortenedUrl(List<String> urls) {
        List<String> shorteners = List.of(
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "is.gd",
                "buff.ly",
                "rebrand.ly"
        );

        for (String url : urls) {
            for (String shortener : shorteners) {
                if (url.contains(shortener)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean containsRawIpUrl(List<String> urls) {
        Pattern ipPattern = Pattern.compile("https?://\\d{1,3}(\\.\\d{1,3}){3}.*");

        for (String url : urls) {
            if (ipPattern.matcher(url).matches()) {
                return true;
            }
        }

        return false;
    }

    private boolean containsSuspiciousTld(List<String> urls) {
        List<String> suspiciousTlds = List.of(
                ".zip",
                ".mov",
                ".click",
                ".top",
                ".xyz",
                ".gq",
                ".tk",
                ".ml"
        );

        for (String url : urls) {
            for (String tld : suspiciousTlds) {
                if (url.contains(tld + "/") || url.endsWith(tld)) {
                    return true;
                }
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