# CST8919 - Assignment 1: Securing and Monitoring an Authenticated Flask App

**Student Name**: Naveed Hossain
**Student ID**: 0410818822
**Course**: CST8919 DevOps - Security and Compliance
**Semester**: Spring/Summer 2026

Combines Lab 1 (Auth0 SSO with `auth0-server-python`) and Lab 2 (Azure App
Service + Log Analytics + KQL alerting) into one app: authenticated users,
structured activity logging, and an alert that fires when a user hits
`/protected` more than 10 times in 15 minutes.

**YouTube demo:** `<PASTE YOUR YOUTUBE LINK HERE>`

---

## 1. What changed from Lab 1 / Lab 2

- `auth.py` is unchanged from Lab 1 - it's just the Auth0 `ServerClient` setup.
- `app.py` keeps every Lab 1 route (`/`, `/login`, `/callback`, `/profile`,
  `/protected`, `/logout`) but adds structured JSON logging around them
  (Section 3), and fixes a duplicate `/protected` route definition that was
  left over in the original Lab 1 file.
- Logging style follows Lab 2's approach (plain `logging` module, stdout ->
  `AppServiceConsoleLogs`) but swaps Lab 2's free-text tags
  (`SUCCESSFUL_LOGIN:` / `FAILED_LOGIN:`) for single-line JSON, so KQL can
  pull out `user_id` / `email` with `parse_json()` instead of matching
  substrings.
- `startup.txt` and `.deployment` are carried over from Lab 2's Azure
  deployment setup.

---

## 2. Setup

### 2.1 Auth0 configuration

1. In the [Auth0 Dashboard](https://manage.auth0.com/), open your existing
   Lab 1 **Regular Web Application** (or create a new one).
2. Under **Settings**, note the **Domain**, **Client ID**, **Client Secret**.
3. Set:
   - **Allowed Callback URLs**:
     `http://localhost:5000/callback, https://<your-app-name>.azurewebsites.net/callback`
   - **Allowed Logout URLs**:
     `http://localhost:5000, https://<your-app-name>.azurewebsites.net`
   - **Allowed Web Origins**:
     `http://localhost:5000, https://<your-app-name>.azurewebsites.net`
4. Save changes.

### 2.2 Local setup

```bash
git clone <your-repo-url>
cd <your-repo>
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate

pip install -r requirements.txt

copy .env.example .env        # macOS/Linux: cp .env.example .env
# edit .env: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_SECRET, AUTH0_REDIRECT_URI

python app.py
```

Visit `http://localhost:5000`, log in, then try `/protected` and `/profile`.

### 2.3 Deploy to Azure App Service

Reusing the Lab 2 setup:

1. Create (or reuse) a **Linux App Service Plan** and **Web App** (Python
   3.11/3.13 runtime).
2. In **Configuration > Application settings**, add: `AUTH0_DOMAIN`,
   `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`,
   `AUTH0_REDIRECT_URI` (set to `https://<your-app-name>.azurewebsites.net/callback`).
3. **Startup Command** (Configuration > General settings):
   ```
   gunicorn --bind=0.0.0.0:8000 app:app
   ```
   (same command as `startup.txt`, matching Lab 2's convention)
4. Deploy, e.g.:
   ```bash
   az webapp up --name <your-app-name> --resource-group <your-rg> --runtime "PYTHON:3.13"
   ```
5. Go back to Auth0 (step 2.1) and make sure the deployed URL is in the
   Allowed Callback/Logout/Web Origins lists.

### 2.4 Enable diagnostic logging to Log Analytics

Same as Lab 2:

1. Web App > **Monitoring > Diagnostic settings > + Add diagnostic setting**.
2. Check **AppServiceConsoleLogs**.
3. Destination: **Send to Log Analytics workspace** (reuse the Lab 2
   workspace, or create one in the same region).
4. Save, then generate traffic (login, `/protected`, an unauthenticated hit)
   and confirm rows appear in `AppServiceConsoleLogs` (allow a few minutes
   for ingestion).

---

## 3. Logging design

Every event is one JSON line via `logger.info()` / `logger.warning()`,
which lands in `AppServiceConsoleLogs.ResultDescription`:

| Event                 | Level   | Fields                                | Emitted from   |
|-----------------------|---------|----------------------------------------|----------------|
| `login_success`       | info    | `user_id`, `email`, `ip`               | `/callback`    |
| `login_error`         | warning | `error`, `ip`                          | `/callback`    |
| `protected_access`    | info    | `user_id`, `email`, `ip`               | `/protected`   |
| `unauthorized_attempt`| warning | `path`, `method`, `ip`, `user_agent`   | `/protected`, `/profile` |
| `logout`              | info    | `user_id`, `email`                     | `/logout`      |

Example raw log line:

```json
{"event": "protected_access", "user_id": "auth0|abc123", "email": "user@example.com", "ip": "20.10.1.5"}
```

---

## 4. KQL detection query

Lab 2's query was a simple substring filter:

```kql
AppServiceConsoleLogs
| where ResultDescription has "FAILED_LOGIN"
```

Assignment 1 extends that idea to a per-user rate check on `/protected`:

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription has "protected_access"
| extend LogData = parse_json(ResultDescription)
| extend user_id = tostring(LogData.user_id)
| where isnotempty(user_id)
| summarize AccessCount = count(), LastAccess = max(TimeGenerated) by user_id
| where AccessCount > 10
| project user_id, LastAccess, AccessCount
| order by AccessCount desc
```

- `parse_json(ResultDescription)` turns the structured log line back into an
  object so `user_id` can be pulled out directly (no substring matching
  needed, unlike Lab 2's `has "FAILED_LOGIN"`).
- `summarize count() by user_id` gives each user's access count within the
  15-minute window.
- `where AccessCount > 10` is the detection threshold.

Companion query for reviewing individual events instead of the aggregate:

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription has "protected_access"
| extend LogData = parse_json(ResultDescription)
| project TimeGenerated, user_id = tostring(LogData.user_id), email = tostring(LogData.email)
| order by TimeGenerated desc
```

---

## 5. Azure Monitor alert rule

1. **Azure Monitor > Alerts > + Create > Alert rule**.
2. **Scope:** the Log Analytics workspace receiving `AppServiceConsoleLogs`.
3. **Condition:** custom log search using the aggregate KQL query above.
   - **Measure:** Table rows
   - **Aggregation granularity:** 15 minutes
   - **Frequency of evaluation:** 5 minutes
   - **Threshold:** Static, Greater than 0 (the query already filters to
     `AccessCount > 10`, so any returned row is a violation)
4. **Actions:** reuse (or recreate) the Lab 2 **Action Group** with an
   **Email** action.
5. **Details:**
   - **Alert rule name:** `Excessive-Protected-Route-Access`
   - **Severity:** `3 - Low`
   - **Description:** "Fires when a single user accesses /protected more
     than 10 times within a 15-minute window."
6. Save.

To test: hit `/protected` more than 10 times as the same logged-in user
within 15 minutes (see `test-app.http` #5-#6), then wait for the next
evaluation cycle (up to 5 minutes) and check for the alert/email.

---

## 6. Repo structure

```
app.py              # Flask + Auth0 SDK app: login/callback/logout/profile/protected + logging
auth.py             # Auth0 ServerClient setup (from Lab 1, unchanged)
requirements.txt
.env.example         # Env var template (no real secrets)
startup.txt          # Azure App Service startup command
.deployment          # Oryx build config (from Lab 2)
templates/
  index.html
  profile.html
  protected.html
static/
  style.css
test-app.http         # REST Client requests: valid/invalid access simulation
README.md
```

---

## 7. Reflection

**What worked:** reusing Lab 1's Auth0 SDK setup and Lab 2's
`AppServiceConsoleLogs` pipeline meant the only new work was the logging
layer and the KQL query itself - both labs' plumbing carried over directly.

**Challenges:** the original Lab 1 `app.py` had a duplicate `/protected`
route definition (harmless in Flask since the second one just gets ignored,
but worth cleaning up); Log Analytics ingestion delay (a few minutes) made
iterating on the KQL query slower than expected.

**Real-world improvements:** correlate `unauthorized_attempt` events by IP
and user agent to catch credential-stuffing patterns, not just excessive
*authenticated* access; move from a static threshold to a per-user baseline;
route alerts to a SIEM instead of only email; automate a response action
(e.g. temporarily blocking the offending IP via a Logic App) rather than
just notifying a human, per the Lab 2 reflection.
