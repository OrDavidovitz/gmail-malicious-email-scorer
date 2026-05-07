# Email Risk Analyzer

A Gmail Add-on backed by a Java Spring Boot service that analyzes the currently opened email and returns an explainable maliciousness score, verdict, risk signals, and recommended action.

The goal of this project is not only to classify an email as suspicious or safe, but to explain why. In security products, a warning is more useful when the user can understand the reasoning behind it. For that reason, the backend uses deterministic, explainable detection signals instead of a black-box model.

## Demo flow

```text
Gmail opened email
      |
      v
Google Apps Script Gmail Add-on
      |
      | JSON over HTTPS
      v
ngrok tunnel, for local demo
      |
      v
Dockerized Spring Boot backend
      |
      v
Detector-based analysis
      |
      v
Score, verdict, signals, and recommended action
      |
      v
Displayed inside Gmail
```

## What the system does

When the user opens an email in Gmail and launches the add-on, the system:

1. Reads the currently opened Gmail message.
2. Extracts selected fields from the message.
3. Sends those fields as JSON to the backend API.
4. Runs sender, content, link, and attachment analysis.
5. Calculates a maliciousness score from 0 to 100.
6. Maps the score to a verdict: LOW, MEDIUM, HIGH, or CRITICAL.
7. Displays the result and the reasoning directly inside Gmail.

Example result:

```text
Maliciousness Score: 80/100
Verdict: CRITICAL

Why this email was flagged:
CONTENT - HIGH
Email asks about login, password, or credential-related actions.

LINK - HIGH
Email contains a shortened URL, which can hide the final destination.

SENDER - HIGH
Sender domain appears to imitate a known brand.
```

## Repository structure

```text
gmail-malicious-email-scorer/
  addon/
    Code.gs
    appsscript.json

  backend/
    Dockerfile
    .dockerignore
    pom.xml
    mvnw
    mvnw.cmd
    .mvn/
    src/
      main/
        java/com/upwind/emailsecurity/
          controller/
          detector/
          model/
          service/
        resources/
      test/
        java/com/upwind/emailsecurity/

  examples/
    phishing-email.json
    benign-email.json

  README.md
```

## Main components

### addon/

Contains the Gmail Add-on code written in Google Apps Script.

Responsibilities:

- Read the currently opened Gmail message.
- Extract only the fields needed by the backend.
- Send a JSON request to the backend.
- Render the score, verdict, risk signals, and recommendation inside Gmail.

### backend/

Contains the Java Spring Boot backend.

Responsibilities:

- Expose the `/api/health` and `/api/analyze` REST endpoints.
- Validate and process incoming email data.
- Run explainable detection logic.
- Return a structured JSON response.

### examples/

Contains sample JSON payloads for manual API testing without Gmail.

## Tech stack

| Layer | Technology | Reason |
|---|---|---|
| Gmail UI | Google Apps Script | Native way to build Gmail and Workspace add-ons |
| Backend | Java 21 and Spring Boot | Structured, production-oriented backend stack |
| API | REST and JSON | Simple, readable, and easy to test |
| Build | Maven | Standard Java dependency and build management |
| Testing | JUnit and Spring Boot Test | Automated verification of core behavior |
| Runtime | Docker | Reproducible backend environment |
| Local demo exposure | ngrok | Temporary HTTPS tunnel from Gmail to local backend |

## API contract

### Health check

```http
GET /api/health
```

Expected response:

```text
Email security backend is running
```

### Analyze email

```http
POST /api/analyze
Content-Type: application/json
X-API-Key: <api-key>
```

The analysis endpoint requires an `X-API-Key` header. For local development, the default key is `dev-secret`. In a real deployment, the key should be provided through an environment variable and stored using managed secret storage.

Request example:

```json
{
  "from": "PayPal Security <security@paypa1-support.com>",
  "replyTo": "support@gmail.com",
  "subject": "Urgent: verify your account now",
  "body": "Your account will be suspended. Click https://bit.ly/verify-paypal-now to verify your password immediately.",
  "attachmentNames": ["invoice.pdf.exe"]
}
```

Response example:

```json
{
  "score": 100,
  "verdict": "CRITICAL",
  "summary": "This email contains several suspicious indicators.",
  "signals": [
    {
      "category": "SENDER",
      "severity": "MEDIUM",
      "message": "Reply-To domain is different from the sender domain.",
      "points": 15
    },
    {
      "category": "LINK",
      "severity": "HIGH",
      "message": "Email contains a shortened URL, which can hide the final destination.",
      "points": 25
    }
  ],
  "recommendedAction": "Do not click links or download attachments. Verify the sender through another trusted channel."
}
```

## Detection model

The backend uses multiple independent detectors. Each detector returns zero or more `RiskSignal` objects. The scoring engine sums the points and converts the score into a verdict.

### SenderDetector

Checks sender-related phishing indicators:

- Reply-To domain differs from From domain.
- Sender claims to represent a known brand but uses a free email provider.
- Sender domain appears to imitate a known brand.
- Sender contains sensitive wording but no valid email address is found.

Lookalike domain detection normalizes common substitutions:

```text
0 -> o
1 -> l
3 -> e
5 -> s
@ -> a
```

It also uses Levenshtein distance to detect domains that are one character edit away from known brands. This is treated as a suspicious signal, not as definitive proof of maliciousness.

### ContentDetector

Checks for social-engineering language in the subject and body:

- Urgency or pressure.
- Account verification or suspension.
- Login, password, or credential requests.
- Payment or billing pressure.
- Prize, reward, or lottery scams.
- Tax refund or government refund themes.

This detector focuses on the behavioral pattern of the message, not only isolated words.

### LinkDetector

Checks URL-related indicators:

- Multiple links.
- Shortened URLs, such as `bit.ly` or `tinyurl.com`.
- Raw IP address links.
- Suspicious or uncommon top-level domains.

The detector does not open links or follow redirects. This is intentional because visiting links can trigger tracking, interact with malicious infrastructure, or create privacy and safety concerns.

### AttachmentDetector

Checks attachment filenames:

- Multiple attachments.
- Risky extensions, such as `.exe`, `.js`, `.vbs`, `.jar`, `.ps1`, `.html`.
- Double-extension tricks, such as `invoice.pdf.exe`.

The detector does not download, open, or inspect attachment content. In a production system, attachment analysis should happen in an isolated sandbox or through a dedicated malware scanning service.

## Scoring

Each risk signal contributes points to the final score.

The raw score is capped at 100.

```text
0-29      LOW
30-59     MEDIUM
60-84     HIGH
85-100    CRITICAL
```

The score is intentionally explainable. A single suspicious indicator does not automatically prove maliciousness. The final verdict is based on the combination of all detected signals.

Example:

```text
Reply-To mismatch                 +15
Lookalike sender domain           +25
Urgency language                  +15
Credential-related language       +20
Shortened URL                     +25
Raw total                         100
Final score                       100
Verdict                           CRITICAL
```

## Running the backend locally

From the backend directory:

```bash
cd backend
EMAIL_ANALYZER_API_KEY=dev-secret ./mvnw spring-boot:run
```

If `EMAIL_ANALYZER_API_KEY` is not provided, the backend falls back to `dev-secret` for local development.

Health check:

```bash
curl http://localhost:8080/api/health
```

Expected response:

```text
Email security backend is running
```

## Running tests

From the backend directory:

```bash
cd backend
./mvnw test
```

The test suite verifies:

- A benign email returns LOW risk.
- A phishing-like email returns CRITICAL risk.
- The score is capped at 100.
- A double-extension attachment is not double-counted as two separate attachment risks.
- The `/api/analyze` endpoint rejects requests without a valid API key.

## Running with Docker

Build the backend image:

```bash
cd backend
docker build -t email-security-backend .
```

Run the container:

```bash
docker run -p 8080:8080 \
  -e EMAIL_ANALYZER_API_KEY=dev-secret \
  email-security-backend
```

Health check:

```bash
curl http://localhost:8080/api/health
```

The backend runs inside the container with Java 21.

The Dockerfile uses a multi-stage build:

1. Build stage: Maven and Java 21 build the Spring Boot jar.
2. Runtime stage: Java 21 JRE runs only the built jar.

This keeps the runtime image cleaner and avoids requiring Java or Maven to be installed on the reviewer machine.

## Manual API testing

From the project root, while the backend is running:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-secret" \
  -d @examples/phishing-email.json
```

Expected result:

```text
score: 100
verdict: CRITICAL
```

Benign example:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-secret" \
  -d @examples/benign-email.json
```

Expected result:

```text
score: 0
verdict: LOW
```

## Gmail Add-on setup

The Gmail Add-on code is located in:

```text
addon/
  Code.gs
  appsscript.json
```

### 1. Create an Apps Script project

Go to:

```text
https://script.google.com
```

Create a new project and copy the contents of:

```text
addon/Code.gs
```

into the Apps Script `Code.gs` file.

### 2. Enable the manifest file

In Apps Script:

1. Open Project Settings.
2. Enable "Show appsscript.json manifest file in editor".
3. Open `appsscript.json`.
4. Copy the contents of `addon/appsscript.json` into the Apps Script manifest file.

### 3. Expose the local backend through HTTPS

Google Apps Script runs in Google cloud, so it cannot call `localhost`.

For local demo, expose the backend with ngrok:

```bash
ngrok http 8080
```

Example output:

```text
Forwarding https://YOUR-NGROK-URL.ngrok-free.dev -> http://localhost:8080
```

Update these constants in `Code.gs`:

```javascript
const BACKEND_URL = 'https://YOUR-NGROK-URL.ngrok-free.dev';
const API_KEY = 'dev-secret';
```

The Apps Script client sends the API key to the backend using the `X-API-Key` header.

Also update the same URL in `appsscript.json`:

```json
"openLinkUrlPrefixes": [
  "https://YOUR-NGROK-URL.ngrok-free.dev"
]
```

### 4. Install test deployment

In Apps Script:

1. Click Deploy.
2. Choose Test deployments.
3. Select Google Workspace Add-on.
4. Install the add-on.
5. Approve the required scopes.

Required scopes:

```text
gmail.addons.execute
gmail.addons.current.message.readonly
script.external_request
```

### 5. Test in Gmail

1. Open Gmail.
2. Open any email.
3. Open the right-side add-on panel.
4. Click Email Risk Analyzer.
5. The score, verdict, signals, and recommendation should appear.

## Security decisions and tradeoffs

### Explainable deterministic scoring

The backend uses deterministic rules instead of an AI model.

Reasons:

- Easier to explain.
- Easier to test.
- Predictable behavior.
- No dependency on third-party model availability.
- No hidden reasoning.

A future version could add an AI layer, but it should complement the explainable signals rather than replace them.

### Minimal data extraction

The add-on sends only selected fields:

```text
from
replyTo
subject
body
attachmentNames
```

It does not send the full Gmail object.

### Attachment content is not downloaded

The system analyzes attachment names and extensions only.

Reasons:

- Reduces privacy exposure.
- Avoids handling potentially malicious files.
- Keeps the first version safer and simpler.

### Links are not opened

The system analyzes URL strings but does not follow redirects or visit links.

Reasons:

- Avoids triggering tracking pixels.
- Avoids interacting with malicious infrastructure.
- Avoids network and sandboxing complexity.

### Input validation

The backend limits field sizes using validation annotations.

Reasons:

- Emails are untrusted input.
- Very large payloads should not be allowed to consume excessive resources.


### API key protection

The `/api/analyze` endpoint requires an `X-API-Key` header.

The backend reads the expected key from the `EMAIL_ANALYZER_API_KEY` environment variable and falls back to `dev-secret` for local development. This keeps the Java backend from hardcoding the secret directly in controller logic and makes the runtime configuration explicit.

This is a lightweight demo-level protection so the exposed backend endpoint is not completely open. In production, this should be replaced with stronger authentication, managed secret storage, request authorization, and rate limiting.

### ngrok is used only for local demo

ngrok is not a production deployment strategy. It is used to let Gmail call a local backend during development.

In production, the backend should be deployed to a managed cloud service behind HTTPS.

## Limitations

This is an MVP built for a home assignment. It intentionally avoids several production-level features:

- No SPF, DKIM, or DMARC header analysis.
- No threat intelligence enrichment.
- No URL redirect expansion.
- No attachment sandboxing.
- Only lightweight shared API key protection is implemented between the add-on and backend. Production should use stronger authentication and managed secret storage.
- No rate limiting.
- No persistent logging or audit trail.
- Heuristic scoring can produce false positives and false negatives.

These limitations are known and documented. The current version focuses on a working, explainable, end-to-end product.

## Production improvements

If this were extended into a production-grade security product, the next steps would be:

- Deploy the Dockerized backend to Google Cloud Run, AWS ECS/Fargate, or Kubernetes.
- Replace the demo API key with stronger authentication between the Gmail Add-on and backend.
- Add rate limiting and abuse protection.
- Add structured logging and monitoring.
- Add safe URL expansion inside an isolated environment.
- Add threat intelligence checks for domains and URLs.
- Add SPF, DKIM, DMARC, and full header analysis.
- Add attachment scanning in a sandbox.
- Add user feedback buttons to improve future scoring.
- Add organization-level policy configuration.

## Design summary

This project separates the Gmail integration layer from the email analysis layer.

The Gmail Add-on is intentionally thin. It reads the current message, sends a structured request, and renders the result.

The Spring Boot backend owns the analysis logic. It is modular, testable, Dockerized, and built around explainable security signals.

This separation makes the system easier to extend, easier to test, and closer to how a real security product would be designed.
