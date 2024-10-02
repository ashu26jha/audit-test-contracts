<div align="center">
<h1><strong> <span style="color:#8660f2"> Audit</span> Agent APIs </strong></h1>
</div>

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Running the Server](#running-the-server)
- [Running the Linters](#running-the-linters)
- [Running Tests](#running-tests)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Running stripe](#running-stripe)
- [Profiles](#profiles)

## Introduction

This is the backend component of the Yokai Audit Agent, providing the core functionality for smart contract auditing, GitHub integration, and user management.

## Getting StartedV

### Prerequisites

- Python 3.12+
- MongoDB
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/NethermindEth/yokai-ai-reviewer.git .
cd backend
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (create a `.env` file in the `backend` directory):
```bash
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-...

LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_HOST=https://...

MONGODB_URL=your_mongodb_url
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

## Running the Server

To launch a local development server:
```bash
cd backend
uvicorn main:app --reload
```

To launch a production server:
```bash
fastapi run
```

To launch a server with Docker:
```bash
cd backend
docker build -t audit-agent-backend -f Dockerfile.backend .
```

then run the following command to run the server:
```bash
docker run -p 8000:8000 audit-agent-backend
```

## Running the Linters

```bash
pre-commit install
pre-commit run --all-files
```

## Running Tests

To run the test suite (Make sure you have launched the local development server):

```bash
pytest backend/tests/ -v
```

To run tests with coverage:

```bash
pytest backend/tests/ -v --cov=backend
```

To generate a coverage report:

```bash
pytest backend/tests/ -v --cov=backend --cov-report=html
```

## API Endpoints

### Authentication Endpoints

<details>
<summary>GET /api/v1/auth/github-login</summary>

Initiates the GitHub OAuth flow for user authentication.

**Response:** Redirects to GitHub for authorization.
</details>

<details>
<summary>GET /api/v1/auth/github-callback</summary>

Handles the callback from GitHub after successful authentication.

**Response:** Sets session/JWT token and redirects to the main application.
</details>

<details>
<summary>POST /api/v1/auth/logout</summary>

Logs out the current user.

**Response:** Clears session/JWT token and returns success message.
</details>

<details>
<summary>GET /api/v1/auth/me</summary>

Retrieves the current authenticated user's information.

**Response:**
```json
{
  "id": "string",
  "username": "string",
  "email": "string",
  "githubId": "string",
  "name": "string",
  "avatarUrl": "string"
}
```
</details>

### GitHub Integration Endpoints

<details>
<summary>GET /api/v1/github/organizations</summary>

Retrieves the list of organizations the authenticated user belongs to.

**Response:** Array of organization objects.
</details>

<details>
<summary>GET /api/v1/github/repositories/{owner}</summary>

Retrieves the list of repositories for a given owner (user or organization).

**Parameters:**
- `owner`: GitHub username or organization name (path parameter)

**Response:** Array of repository objects.
</details>

<details>
<summary>GET /api/v1/github/repository-contents/{owner}/{repo}</summary>

Retrieves the contents of a specific repository.

**Parameters:**
- `owner`: GitHub username or organization name (path parameter)
- `repo`: Repository name (path parameter)

**Response:** Array of file/directory objects.
</details>

<details>
<summary>GET /api/v1/github/repository-info</summary>

Retrieves information about a specific GitHub repository.

**Parameters:**
- `repo_url`: Full URL of the GitHub repository (query parameter)

**Response:**
```json
{
  "success": true,
  "data": {
    "repo_url": "string",
    "repo_name": "string",
    "repo_full_name": "string",
    "created_at": "Datetime",
    "updated_at": "Datetime"
  }
}
```
</details>

### Scanning Endpoints

<details>
<summary>POST /api/v1/audit-agent</summary>

Initiates a new scan for selected smart contracts.

**Request Body:**
```json
{
  "repositoryURL": "string",
  "contractFiles": ["string"],
  "branchName": "string"
}
```

**Response:**
```json
{
	"success": true,
	"data": {
		"scan_id": "UUID"
	}
}
```
</details>

<details>
<summary>GET /api/v1/scans/full/{scan_id}</summary>

Retrieves the full results of a specific scan (Only available in development mode)

**Parameters:**
- `scan_id`: UUID of the scan (path parameter)

**Response:**
```json
{
	"success": true,
	"data": {
    "scan": {
			"scan_id": "UUID",
      "scan_number": "number",
			"status": "string",
			"startedAt": "Datetime",
			"completedAt": "Datetime",
			"contractFiles": [ "string"],
			"linesOfCode": {
				"total_lines": "number",
				"code_lines": "number",
				"comment_lines": "number",
				"empty_lines": "number",
				"string_lines": "number",
			},
			"branchName": "main",
			"commitHash": "001",
			"paid_status": "boolean",
		},
		"partial_result": {
      "scan_id": "UUID",
      "scan_number": "number",
      "summary": "string",
      "type": "string",
      "findings": [
        {
          "Issue": "string",
          "Severity": "string",
          "Contracts": ["string"],
          "Description": "string",
          "Recommendation": "string"
        }
      ],
      "createdAt": "DateTime",
      "updatedAt": "DateTime",
    }
  }
}
```
</details>

<details>
<summary>GET /api/v1/scans/partial/{scan_id}</summary>

Retrieves partial results of a specific scan (limited findings).

**Parameters:**
- `scan_id`: UUID of the scan (path parameter)

**Response:**
```json
{
	"success": true,
	"data": {
    "scan": {
			"scan_id": "UUID",
      "scan_number": "number",
			"status": "string",
			"startedAt": "DateTime",
			"completedAt": "DateTime",
			"contractFiles": [ "string"],
			"linesOfCode": {
				"total_lines": "number",
				"code_lines": "number",
				"comment_lines": "number",
				"empty_lines": "number",
				"string_lines": "number",
			},
			"branchName": "string",
			"commitHash": "string",
			"paid_status": "boolean",
		},
		"partial_result": {
      "scan_id": "UUID",
      "scan_number": "number",
      "summary": "string",
      "type": "string",
      "findings": [
        {
          "Issue": "string",
          "Severity": "string",
          "Contracts": ["string"],
          "Description": "string",
          "Recommendation": "string"
        }
      ],
      "createdAt": "DateTime",
      "updatedAt": "DateTime",
    }
  }
}
```

</details>

<details>
<summary>GET /api/v1/scans-history</summary>

Retrieves the scan history for the authenticated user.

**Response:**
An array of scan objects, each including:
```json
{
	"success": true,
	"data": [
    "scan_id": "UUID",
    "scan_number": "number",
    "status": "String",
    "startedAt": "DateTime",
    "completedAt": "DateTime",
    "contractFiles": ["string"],
    "linesOfCode": {
				"total_lines": "number",
				"code_lines": "number",
				"comment_lines": "number",
				"empty_lines": "number",
				"string_lines": "number",
			},
			"branchName": "string",
			"commitHash": "string",
			"paid_status": "boolean",
  ],
}
```
</details>

<details>
<summary>GET /api/v1/generate-pdf/{scan_id}</summary>

Generates a PDF report for a specific scan and send it to the user's email.

**Parameters:**
- `scan_id`: UUID of the scan (path parameter)

**Response:**
An array of scan objects, each including:
```json
{
	"success": true,
	"data": "PDF send by email successfully"
}
```
</details>

### Miscellaneous Endpoints

<details>
<summary>GET /api/v1/health-check</summary>

Simple health check endpoint to verify API status.

**Response:**
```json
{
	"success": "boolean",
	"data": {
		"details": "string",
    "version": "string"
	}
}
```
</details>

<details>
<summary>POST /api/v1/generate-summary</summary>

Generates a summary of smart contracts.

**Request Body:**
```json
{
  "contracts": "string"
}
```

**Response:**
```json
{
	"success": true,
	"data": {
    "summary": "string",
    "type": "string"
  }
}
```
</details>

<details>
<summary>POST /api/v1/context-scan</summary>

Performs a context-aware scan of smart contracts.

**Request Body:**
```json
{
  "summary": "string (optional)",
  "contracts": "string",
  "profile": "string (optional)"
}
```

**Response:**
```json
{
	"success": true,
	"data": {
    "findings": [
        {
        "Issue": "string",
        "Severity": "string",
        "Contracts": ["string"],
        "Description": "string",
        "Recommendation": "string"
      }
    ]
  }
}
```
</details>

<details>
<summary>POST /api/v1/test-auth/token</summary>

In development mode, you can generate JWT tokens for testing purposes using the `/api/v1/test-auth/token` endpoint.

**Request Body:**

- `username`: The username for which you want to generate a token.

**Example Request:**

```bash
curl -X POST "http://localhost:8000/test-auth/token" \
    -H "Content-Type: application/json" \
    -d '{"username": "testuser"}'
```

**Response:**

```json
{
	"success": true,
	"data": {
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer",
    "user": {
      "_id": "652f64e8c324d4eb783d4a61",
      "username": "testuser",
      "email": "testuser@example.com",
      "githubId": "test_github_id",
      "accessToken": "test_access_token",
      "createdAt": "2023-10-01T12:00:00Z",
      "updatedAt": "2023-10-01T12:00:00Z"
    }
  }
}
```
</details>

**Note:** This endpoint is only available in development mode and is disabled in production.

## Database Schema

### Users Collection

```json
{
  "_id": "ObjectId",
  "username": "string",
  "email": "string",
  "githubId": "string",
  "accessToken": "string",
  "avatarUrl": "string",
  "createdAt": "Datetime",
  "updatedAt": "Datetime",
  "lastLoginAt": "Datetime"
}
```

### Repositories Collection

```json
{
  "_id": "ObjectId",
  "githubId": "String",
  "name": "String",
  "owner": "String",
  "description": "String",
  "url": "String",
  "createdAt": "Date",
  "updatedAt": "Date",
  "userId": "ObjectId"
}
```

### Scans Collection

```json
{
  "_id": "ObjectId",
  "scan_id": "UUID",
  "scan_number": "number",
  "user_id": "ObjectId",
  "status": "string",
  "startedAt": "Datetime",
  "completedAt": "Datetime",
  "contractFiles": ["string"],
  "linesOfCode": {
    "total_lines": "number",
    "code_lines": "number",
    "comment_lines": "number",
    "empty_lines": "number",
    "string_lines": "number",
  },
  "repositoryURL": "string",
  "repositoryName": "string",
  "branchName": "string",
  "commitHash": "string",
  "paid_status": "boolean",
  "createdAt": "Datetime",
  "updatedAt": "Datetime"
}
```

### Scan Results Collection

```json
{
  "_id": "ObjectId",
  "scan_id": "UUID",
  "scan_number": "number",
  "summary": "string",
  "type": "string",
  "findings": [
    {
      "Issue": "string",
      "Severity": "string",
      "Contracts": ["string"],
      "Description": "string",
      "Recommendation": "string"
    }
  ],
  "createdAt": "Datetime",
  "completedAt": "Datetime",
}
```

### Payments Collection

```json
{
  "_id": "ObjectId",
  "event_id": "string",
  "user_id": "ObjectId",
  "scan_id": "ObjectId",
  "amount": "number",
  "currency": "string",
  "status": "string",
  "stripeSessionId": "string",
  "createdAt": "Datetime",
  "updatedAt": "Datetime"
}
```

## Running stripe:

> Read the [Stripe docs](https://docs.stripe.com/webhooks?lang=python#webhooks-summary) to setup webhook. The callback endpoint needs to be registered in the Stripe dashboard.

> Note that `WEBHOOK_SECRET` for local deployment is generated in CLI (detail steps below)

Fill the `STRIPE_API_KEY` and `WEBHOOK_SECRET` in the `.env` file.

You need to send a post request to `http://localhost:8000/api/v1/payments/create-stripe-session`

```json
{
    "scanId": "String"
}
```

The response is:
```json
{
  "session_id": "String",
  "URL": "String"
}
```

### To be able to use webhooks
1. Install stripe CLI: [Stripe CLI Documentation](https://docs.stripe.com/stripe-cli)

2. Login using: 
```bash 
stripe login
```

3. Run the following command to start the webhook listener:
```bash
stripe listen --forward-to http://localhost:8000/api/v1/payments/stripe-webhook
```

4. The response of above command will be like, and paste your webhook URL:
```bash
Your webhook signing secret is whsec_ (^C to quit)
```

## Profiles

<details>
  <summary>DeFi</summary>
  <ul>
    <li>Total token: 34,865</li>
    <li>NM0067: Tokens Input: 3,462</li>
    <li>NM0074: Tokens Input: 18,726</li>
    <li>NM0108: Tokens Input: 1,351</li>
    <li>NM0227: Tokens Input: 11,326</li>
  </ul>
</details>

<details>
  <summary>NFT</summary>
  <ul>
    <li>NFT & Gaming, etc. Total token: 27,172</li>
    <li>NM0062: Tokens Input: 1,627</li>
    <li>NM0070: Tokens Input: 5,601</li>
    <li>NM0073: Tokens Input: 6,234</li>
    <li>NM0225: Tokens Input: 13,707</li>
  </ul>
</details>

<details>
  <summary>Utility</summary>
  <ul>
    <li>L2 Bridge & Oracle, etc. Total tokens: 25,001</li>
    <li>NM0081: Tokens Input: 6,753</li>
    <li>NM0234: Tokens Input: 6,254</li>
    <li>NM0245: Tokens Input: 11,994</li>
  </ul>
</details>

<details>
  <summary>Identity</summary>
  <ul>
    <li>Identity Management & Wallets, etc. Total tokens: 31,659</li>
    <li>NM0069: Tokens Input: 7,888</li>
    <li>NM0083: Tokens Input: 1,715</li>
    <li>NM0113: Token Input: 17,885</li>
    <li>NM0160: Token Input: 4,171</li>
  </ul>
</details>

<details>
  <summary>DAO</summary>
  <ul>
    <li>Governance, etc. Total tokens: 29,347</li>
    <li>NM00096: Tokens Input: 29,347</li>
  </ul>
</details>

<details>
  <summary>Default</summary>
  <ul>
    <li>Total tokens: 30,934</li>
    <li>NM0062: Tokens Input: 1,627</li>
    <li>NM0067: Tokens Input: 3,462</li>
    <li>NM0070: Tokens Input: 5,601</li>
    <li>NM0081: Token Input: 6,753</li>
    <li>NM0083: Tokens Input: 1,715</li>
    <li>NM0108: Tokens Input: 1,351</li>
    <li>NM0160: Token Input: 4,171</li>
    <li>NM0234: Tokens Input: 6,254</li>
  </ul>
</details>

