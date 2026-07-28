# CST8919 - Assignment 1: Securing and Monitoring an Authenticated Flask App

**Student Name**: Naveed Hossain
**Student ID**: 0410818822
**Course**: CST8919 DevOps - Security and Compliance
**Semester**: Spring/Summer 2026



---

A Flask web app that uses Auth0 for login, is deployed to Azure App Service, and logs user activity to Azure Monitor. An alert is triggered when a user accesses the protected page too many times.

**YouTube Demo:** <PASTE YOUR YOUTUBE LINK HERE>

## Features

- Auth0 authentication
- Protected route (`/protected`)
- JSON logging
- Azure Monitor + Log Analytics
- Alert for excessive access

## Setup

1. Clone the repository.
2. Copy `.env.example` to `.env` and add your Auth0 values.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the app:

```bash
python app.py
```

Open: `http://localhost:5000`

## Deploy to Azure

Deploy the app to Azure App Service and add your Auth0 settings as Application Settings.

Update your Auth0 application with your Azure app URL for:
- Callback URL
- Logout URL
- Web Origin

## Logging

The app logs these events as JSON:

- `login_success`
- `protected_access`
- `unauthorized_attempt`
- `logout`

Example:

```json
{"event":"protected_access","user_id":"auth0|123","email":"user@example.com","ip":"1.2.3.4"}
```

## Monitoring

Enable **AppServiceConsoleLogs** and send them to a Log Analytics Workspace.

KQL query:

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription has "protected_access"
| extend LogData = parse_json(ResultDescription)
| extend user_id = tostring(LogData.user_id)
| summarize AccessCount = count() by user_id
| where AccessCount > 10
```

## Alert

Create an Azure Monitor alert:

- **Scope:** Log Analytics Workspace
- **Condition:** Query returns more than 0 rows
- **Action:** Email
- **Severity:** 3

The alert triggers when a user accesses `/protected` more than **10 times in 15 minutes**.
