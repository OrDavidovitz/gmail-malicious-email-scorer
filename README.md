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
Cloud Run HTTPS service
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

Example Gmail card output:

```text
Maliciousness Score: 100/100
Verdict: CRITICAL

Summary:
This email contains several suspicious indicators.

Recommended action:
Do not click links or download attachments. Verify the sender through another trusted channel.

Why this email was flagged:
ATTACHMENT - HIGH
Email contains an attachment using a double-extension trick.
Points: 30

LINK - HIGH
Email contains a shortened URL, which can hide the final destination.
Points: 25

SENDER - HIGH
Sender domain appears to imitate a known brand.
Points: 25

CONTENT - HIGH
Email asks about login, password, or credential-related actions.
Points: 20

CONTENT - MEDIUM
Email uses urgent or pressure-based language.
Points: 15
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
| Cloud deployment | Google Cloud Run | Managed HTTPS runtime for the Dockerized backend |

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

The analysis endpoint requires an `X-API-Key` header. The backend reads the expected key from the `EMAIL_ANALYZER_API_KEY` environment variable. The Gmail Add-on reads the client-side key from Apps Script Script Properties using the same property name.

The endpoint also applies basic rate limiting. If the request limit is exceeded, it returns `429 Too Many Requests`.

Do not commit real API keys to the repository. Use a throwaway local value for development and a separate value for deployed environments.

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
EMAIL_ANALYZER_API_KEY=<YOUR_API_KEY> ./mvnw spring-boot:run
```

Set `EMAIL_ANALYZER_API_KEY` to the same value that the client sends in the `X-API-Key` header. Use a throwaway value for local development and do not commit real secrets.

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
- The `/api/analyze` endpoint returns `429 Too Many Requests` when the API key exceeds the request limit.

## Running with Docker

Build the backend image:

```bash
cd backend
docker build -t email-security-backend .
```

Run the container:

```bash
docker run -p 8080:8080 \
  -e EMAIL_ANALYZER_API_KEY=<YOUR_API_KEY> \
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

## Deploying to Cloud Run

The backend is containerized, so it can be deployed directly to Google Cloud Run.

The submitted demo uses Cloud Run as the public HTTPS backend for the Gmail Add-on:

```text
https://email-security-backend-557464179156.europe-west1.run.app
```

Enable the required Google Cloud services:

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
```

Deploy from the backend directory:

```bash
cd backend
gcloud run deploy email-security-backend \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --set-env-vars EMAIL_ANALYZER_API_KEY=<YOUR_API_KEY>
```

The `--source .` flag lets Cloud Build build the container from the backend source and Dockerfile. Cloud Run then runs the built container as a managed HTTPS service.

The service is publicly reachable because Gmail Apps Script needs to call it over HTTPS. The `/api/analyze` endpoint is still protected by the `X-API-Key` header.

Cloud Run health check:

```bash
curl https://email-security-backend-557464179156.europe-west1.run.app/api/health
```

Analyze endpoint without API key:

```bash
curl -i -X POST https://email-security-backend-557464179156.europe-west1.run.app/api/analyze \
  -H "Content-Type: application/json" \
  -d @examples/phishing-email.json
```

Expected result:

```text
HTTP/2 401
```

Analyze endpoint with API key:

```bash
curl -i -X POST https://email-security-backend-557464179156.europe-west1.run.app/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <YOUR_API_KEY>" \
  -d @examples/phishing-email.json
```

Expected result:

```text
HTTP/2 200
score: 100
verdict: CRITICAL
```

Cloud Run is still not a complete production setup by itself. A production version should use stronger authentication, managed secrets, distributed edge rate limiting, structured logging, monitoring, and alerting.

## Manual API testing

From the project root, while the backend is running:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <YOUR_API_KEY>" \
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
  -H "X-API-Key: <YOUR_API_KEY>" \
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

### 3. Configure the backend URL

Google Apps Script runs in Google cloud, so it cannot call `localhost`.

The submitted version uses the deployed Cloud Run backend:

```javascript
const BACKEND_URL = 'https://email-security-backend-557464179156.europe-west1.run.app';
const API_KEY_PROPERTY_NAME = 'EMAIL_ANALYZER_API_KEY';
```

The API key itself is not hardcoded in `Code.gs`. Store it in Apps Script under Project Settings -> Script properties:

```text
EMAIL_ANALYZER_API_KEY=<YOUR_API_KEY>
```

The Apps Script client reads the property at runtime and sends it to the backend using the `X-API-Key` header.

The same Cloud Run URL should appear in `appsscript.json`:

```json
"openLinkUrlPrefixes": [
  "https://email-security-backend-557464179156.europe-west1.run.app"
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

### Sensitive data masking

Before sending the subject and body to the backend, the Gmail Add-on masks common sensitive patterns such as card-like numbers, ID-like numbers, and phone-like numbers.

This reduces unnecessary exposure of sensitive data while still allowing the backend to analyze phishing language. This is a lightweight privacy layer, not a complete DLP system.

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

The backend reads the expected key from the `EMAIL_ANALYZER_API_KEY` environment variable. The Gmail Add-on reads the client-side value from Apps Script Script Properties using the same property name.

This avoids committing the actual key in the repository and keeps runtime configuration explicit. The current implementation is still lightweight demo-level protection, so in production it should be replaced with stronger authentication, managed secret storage, request authorization, and distributed rate limiting.

### Basic rate limiting

The `/api/analyze` endpoint includes a lightweight application-level rate limiter.

The current implementation allows up to 30 analysis requests per 60-second window per API key. If the limit is exceeded, the backend returns `429 Too Many Requests`.

This protects the public Cloud Run endpoint from simple abuse during the demo. The limiter is intentionally lightweight and in-memory. In production, rate limiting should be enforced at the edge or through a shared backing store because Cloud Run can scale to multiple instances.

### Cloud Run deployment

The backend is deployed to Google Cloud Run as a managed HTTPS service. This removes the need for ngrok in the main demo and better represents the production direction of the system.

Cloud Run runs the same Dockerized Spring Boot backend that can also be executed locally. This keeps local development and cloud deployment aligned.

The Cloud Run service is publicly reachable so that Google Apps Script can call it, but the analysis endpoint still requires the `X-API-Key` header.

### Development note

During early local development, the backend was tested through a temporary HTTPS tunnel because Google Apps Script cannot call `localhost` directly.

The submitted version no longer depends on a tunnel. The Gmail Add-on is configured to call the deployed Cloud Run backend.

## Threat model

This project assumes that email content, attachment names, links, sender metadata, and backend responses are untrusted.

Main risks considered:

- Malicious or oversized email content sent to the backend.
- Suspicious links designed to track users or redirect to malicious infrastructure.
- Attachments with risky extensions or deceptive double extensions.
- Sender spoofing, reply-to mismatch, and lookalike domains.
- Public exposure of the Cloud Run backend endpoint.
- Unexpected text rendered inside the Gmail Add-on UI.

Mitigations implemented:

- The backend validates request field sizes.
- The add-on sends only selected fields instead of the full Gmail object.
- The add-on masks common sensitive patterns before sending subject/body text to the backend.
- Attachment contents are not downloaded or opened.
- Links are not opened, followed, or expanded.
- Displayed text is escaped before rendering inside the Gmail card.
- The `/api/analyze` endpoint requires an `X-API-Key` header.
- The backend applies basic rate limiting to the analysis endpoint.
- The backend reads the API key from an environment variable, and the add-on reads it from Apps Script Script Properties.

Remaining risks:

- The shared API key is demo-level protection, not full production authentication.
- The system does not verify SPF, DKIM, DMARC, or full raw email headers.
- The system does not use threat intelligence or sandboxed URL/attachment analysis.
- Heuristic detection can produce false positives and false negatives.

## Limitations

This is an MVP built for a home assignment. It intentionally avoids several production-level features:

- No SPF, DKIM, or DMARC header analysis.
- No threat intelligence enrichment.
- No URL redirect expansion.
- No attachment sandboxing.
- Sensitive data masking is regex-based and not a complete DLP solution.
- Only lightweight shared API key protection is implemented between the add-on and backend. Production should use stronger authentication and managed secret storage.
- Rate limiting is implemented in-memory and is not distributed across multiple Cloud Run instances.
- No persistent logging or audit trail.
- Heuristic scoring can produce false positives and false negatives.

These limitations are known and documented. The current version focuses on a working, explainable, end-to-end product.

## Production improvements

If this were extended into a production-grade security product, the next steps would be:

- Move the API key to managed secret storage, such as Google Secret Manager.
- Replace the demo API key with stronger authentication between the Gmail Add-on and backend.
- Move rate limiting to the edge, for example API Gateway, Cloud Armor, or a shared distributed store.
- Add structured logging and monitoring.
- Add safe URL expansion inside an isolated environment.
- Replace regex-based masking with a proper DLP pipeline for sensitive data detection.
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
