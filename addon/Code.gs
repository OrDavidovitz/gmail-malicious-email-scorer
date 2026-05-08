const BACKEND_URL = 'https://email-security-backend-557464179156.europe-west1.run.app';
const API_KEY = 'dev-secret';

function onGmailMessageOpen(e) {
try {
GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

const message = GmailApp.getMessageById(e.gmail.messageId);
const payload = buildEmailPayload(message);
const result = analyzeEmail(payload);

return buildResultCard(result);
} catch (error) {
return buildErrorCard(error);
}
}

function buildEmailPayload(message) {
const attachments = message.getAttachments() || [];
const attachmentNames = attachments.map(function(attachment) {
return attachment.getName();
});

return {
from: message.getFrom(),
replyTo: message.getReplyTo(),
subject: message.getSubject(),
body: message.getPlainBody(),
attachmentNames: attachmentNames
};
}

function analyzeEmail(payload) {
const response = UrlFetchApp.fetch(BACKEND_URL + '/api/analyze', {
method: 'post',
contentType: 'application/json',
payload: JSON.stringify(payload),
muteHttpExceptions: true
});

const statusCode = response.getResponseCode();
const responseText = response.getContentText();

if (statusCode < 200 || statusCode >= 300) {
throw new Error('Backend returned status ' + statusCode + ': ' + responseText);
}

return JSON.parse(responseText);
}

function buildResultCard(result) {
const section = CardService.newCardSection();

section.addWidget(
CardService.newKeyValue()
.setTopLabel('Maliciousness Score')
.setContent(result.score + '/100')
);

section.addWidget(
CardService.newKeyValue()
.setTopLabel('Verdict')
.setContent(result.verdict)
);

section.addWidget(
CardService.newTextParagraph()
.setText('<b>Summary:</b><br>' + escapeHtml(result.summary))
);

section.addWidget(
CardService.newTextParagraph()
.setText('<b>Recommended action:</b><br>' + escapeHtml(result.recommendedAction))
);

if (result.signals && result.signals.length > 0) {
section.addWidget(
CardService.newTextParagraph()
.setText('<b>Why this email was flagged:</b>')
);

const sortedSignals = result.signals.slice().sort(function(a, b) {
  return b.points - a.points;
});

sortedSignals.forEach(function(signal) {
  section.addWidget(
    CardService.newTextParagraph()
      .setText(
        '<b>' + escapeHtml(signal.category) + ' - ' + escapeHtml(signal.severity) + '</b><br>' +
        escapeHtml(signal.message) +
        '<br><i>Points: ' + signal.points + '</i>'
      )
  );
});
} else {
section.addWidget(
CardService.newTextParagraph()
.setText('No suspicious indicators were detected.')
);
}

return CardService.newCardBuilder()
.setHeader(
CardService.newCardHeader()
.setTitle('Email Risk Analysis')
.setSubtitle('Explainable phishing risk score')
)
.addSection(section)
.build();
}

function buildErrorCard(error) {
const section = CardService.newCardSection()
.addWidget(
CardService.newTextParagraph()
.setText(
'<b>Analysis failed</b><br>' +
escapeHtml(error.message)
)
);

return CardService.newCardBuilder()
.setHeader(
CardService.newCardHeader()
.setTitle('Email Risk Analysis')
.setSubtitle('Could not analyze this email')
)
.addSection(section)
.build();
}

function escapeHtml(value) {
if (value === null || value === undefined) {
return '';
}

return String(value)
.replace(/&/g, '&amp;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;');
}