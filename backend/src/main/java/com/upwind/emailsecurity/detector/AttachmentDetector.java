package com.upwind.emailsecurity.detector;

import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class AttachmentDetector {

    public List<RiskSignal> detect(EmailAnalysisRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        List<String> attachmentNames = request.getAttachmentNames();

        if (attachmentNames == null || attachmentNames.isEmpty()) {
            return signals;
        }

        if (attachmentNames.size() >= 3) {
            signals.add(new RiskSignal(
                    "ATTACHMENT",
                    "LOW",
                    "Email contains multiple attachments.",
                    10
            ));
        }

        if (containsDoubleExtension(attachmentNames)) {
            signals.add(new RiskSignal(
                    "ATTACHMENT",
                    "HIGH",
                    "Email contains an attachment using a double-extension trick.",
                    30
            ));
        } else if (containsRiskyExtension(attachmentNames)) {
            signals.add(new RiskSignal(
                    "ATTACHMENT",
                    "HIGH",
                    "Email contains an attachment with a potentially dangerous file extension.",
                    30
            ));
        }

        return signals;
    }

    private boolean containsRiskyExtension(List<String> attachmentNames) {
        List<String> riskyExtensions = List.of(
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".js",
                ".vbs",
                ".jar",
                ".ps1",
                ".iso",
                ".html",
                ".htm"
        );

        for (String attachmentName : attachmentNames) {
            String lowerName = safeLower(attachmentName);

            for (String extension : riskyExtensions) {
                if (lowerName.endsWith(extension)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean containsDoubleExtension(List<String> attachmentNames) {
        List<String> commonDocumentExtensions = List.of(
                ".pdf",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".jpg",
                ".jpeg",
                ".png"
        );

        List<String> executableExtensions = List.of(
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".js",
                ".vbs",
                ".jar",
                ".ps1",
                ".html",
                ".htm"
        );

        for (String attachmentName : attachmentNames) {
            String lowerName = safeLower(attachmentName);

            for (String documentExtension : commonDocumentExtensions) {
                for (String executableExtension : executableExtensions) {
                    if (lowerName.contains(documentExtension + executableExtension)) {
                        return true;
                    }
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