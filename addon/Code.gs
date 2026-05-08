const BACKEND_URL = 'https://email-security-backend-557464179156.europe-west1.run.app';
const API_KEY_PROPERTY_NAME = 'EMAIL_ANALYZER_API_KEY';

function onGmailMessageOpen(e) {
try {
GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

const message = GmailApp.getMessageById(e.gmail.messageId);
const payload = buildEmailPayload(message, e.gmail.messageId);
const result = analyzeEmail(payload);

return buildResultCard(result);
} catch (error) {
return buildErrorCard(error);
}
}

function buildEmailPayload(message, messageId) {
  const attachments = message.getAttachments() || [];
  const attachmentNames = attachments.map(function(attachment) {
    return attachment.getName();
  });

  return {
    from: message.getFrom(),
    replyTo: message.getReplyTo(),
    subject: maskSensitiveText(message.getSubject()),
    body: maskSensitiveText(message.getPlainBody()),
    authenticationResults: getAuthenticationResultsHeader(messageId),
    attachmentNames: attachmentNames
  };
}

function analyzeEmail(payload) {
  const apiKey = getApiKey();

  const response = UrlFetchApp.fetch(BACKEND_URL + '/api/analyze', {
    method: 'post',
    contentType: 'application/json',
    headers: {
      'X-API-Key': apiKey
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const statusCode = response.getResponseCode();
  const responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error('Backend returned status ' + statusCode);
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
  console.error(error);

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          '<b>Security scan is currently unavailable.</b><br>' +
          'Please try again later. If the issue continues, verify that the backend service is reachable.'
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

function maskSensitiveText(value) {
  if (value === null || value === undefined) {
    return '';
  }

  return String(value)
    .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[MASKED_CARD]')
    .replace(/\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g, '[MASKED_ID]')
    .replace(/\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{2,3}[-.\s]?\d{7}|\d{3}[-.\s]?\d{3}[-.\s]?\d{4})\b/g, '[MASKED_PHONE]');
}

function getApiKey() {
  const apiKey = PropertiesService
    .getScriptProperties()
    .getProperty(API_KEY_PROPERTY_NAME);

  if (!apiKey) {
    throw new Error('Missing Apps Script property: ' + API_KEY_PROPERTY_NAME);
  }

  return apiKey;
}

function getAuthenticationResultsHeader(messageId) {
  try {
    const response = Gmail.Users.Messages.get('me', messageId, {
      format: 'metadata',
      metadataHeaders: ['Authentication-Results', 'ARC-Authentication-Results']
    });

    const headers = response.payload && response.payload.headers
      ? response.payload.headers
      : [];

    const values = headers
      .filter(function(header) {
        return header.name === 'Authentication-Results' ||
               header.name === 'ARC-Authentication-Results';
      })
      .map(function(header) {
        return header.value;
      });

    return values.join('\n');
  } catch (error) {
    console.error(error);
    return '';
  }
}