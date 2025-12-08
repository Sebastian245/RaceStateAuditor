Race State Auditor

Advanced Concurrency Verification for Burp Suite

Race State Auditor is a professional extension designed to detect and validate Race Conditions by analyzing application state changes, rather than relying solely on HTTP status codes.

Unlike standard brute-force tools, this extension implements a State Probe workflow that verifies if a concurrent attack successfully bypassed business logic limits (e.g., duplication, negative balance, limit evasion) even when the server returns generic 200 OK responses.

Core Capabilities

1. State-Aware Verification

The engine executes pre-flight and post-flight probe requests to measure the exact impact of the attack on the backend database.

Idempotency Detection: Distinguishes between safe request repetitions (1 resource created) and critical race conditions (N resources created).

Silent Failure Detection: Identifies scenarios where HTTP responses indicate failure (400/500), but the backend processed the data anyway.

2. Heuristic Risk Analysis

Results are classified using a semantic risk matrix:

🔴 CRITICAL: Explicit Duplication. The probe detected multiple new resources generated from the concurrent burst.

🟠 HIGH: Silent Duplication. HTTP layer reported errors, but the state changed significantly.

🟡 MEDIUM: State Change / Potential Idempotency.

🟢 SAFE: Concurrency limits were respected.

3. Smart Probe Engine

The verification logic supports:

Regex Extraction: Capture specific values (e.g., balance: (\d+)).

Occurrence Counting: Automatically counts how many times a string appears to detect duplication.

Normalized Matching: Ignores whitespace/formatting differences in HTML responses.

4. Transport Synchronization

HTTP/2 Multiplexing: Optional mode to send concurrent requests over a single TCP connection, minimizing network jitter (Single-Packet Attack approximation).

Workflow

Select Target: Right-click a request in Burp and select Send to Race State Auditor.

Define Probe (Optional):

In the Probe Request tab, load a request that checks the state (e.g., GET /my-coupons).

Enter a string to track (e.g., a specific coupon ID).

Audit: Click Start Analysis. The tool will:

Check initial count.

Synchronize and fire 20 threads.

Check final count.

Verdict: Review the risk assessment and detailed logs.

Installation

Download RaceStateAuditor.jar from Releases.

In Burp Suite, go to Extensions -> Add.

Select the JAR file.

Requirements: Java 17+, Burp Suite Professional/Community 2023.1+.

License

MIT License.
