<div align="center">
<h1><strong> <span style="color:#8660f2"> Audit</span> Agent APIs </strong></h1>
</div>

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [How to run the backend separately](#how-to-run-the-backend-separately)
  - [Install dependencies](#install-dependencies)
  - [Run the server](#run-the-server)
  - [Run the Linters](#run-the-linters)
  - [Run the Tests](#run-the-tests)
  - [Run Stripe](#run-stripe)
- [Backend Structure](#backend-structure)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Profiles](#profiles)

## Introduction

This is the backend component of Audit Agent, providing the core functionality for smart contract auditing, GitHub integration, and user management.

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 20+
- MongoDB
- Git
- Docker

### Installation

Clone the repository:
```bash
git clone https://github.com/NethermindEth/yokai-ai-reviewer.git .
cd backend
```

### Configure environment variables

Copy the `.env.example` file to `.env` and set the following variables:

> **NOTE: If you are coming from the parent [readme](../README.md) and want to run both frontend and backend together, you just need to configure the environment variables below. No need to run the backend separately**

```bash
ADMIN_API_KEY="Use the same value defined in the frontend"
AGENTIC_API_KEY="Your_agentic_api_key" # Only needed for Agentic scans
ETHERSCAN_API_KEY="Your_etherscan_api_key" # Only needed for Agentic scans
SECRET_KEY="Any key for JWT token"

# For AI services
OPENAI_API_KEY="Your_openai_api_key"
ANTHROPIC_API_KEY="Your_anthropic_api_key"
GEMINI_API_KEY="Your_gemini_api_key"

# For Langfuse monitoring (Ask for the keys)
LANGFUSE_SECRET_KEY="Your_langfuse_secret_key"
LANGFUSE_PUBLIC_KEY="Your_langfuse_public_key"
LANGFUSE_HOST="Your_langfuse_host"

# Create a MongoDB and get the URL (Create your own to mess with)
MONGODB_URL="Your_mongodb_url"

# Create a Github app and get the client ID and secret
GITHUB_CLIENT_ID="Your_github_client_id"
GITHUB_CLIENT_SECRET="Your_github_client_secret"
GITHUB_INSTALLATION_URL=your_github_installation_url

# Create a Stripe account and get the API keys
STRIPE_API_KEY="sk..."
STRIPE_WEBHOOK_SECRET=wk # Check readme for more details
STRIPE_ENTERPRISE_PRICE_ID=price_yourPriceIdHere
STRIPE_PRO_PRICE_ID=price_yourPriceIdHere

# For email notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
```

## How to run the backend separately

### Install dependencies:

For production environment:
```bash
pip install -r requirements.txt
```

For development environment (includes testing and linting tools):
```bash
pip install -r requirements.dev.txt
```

### Run the server

To launch a local development server (PDF generation not working):
```bash
uvicorn main:app --reload
```

To launch a local development server with Docker (PDF generation OK):
```bash
docker build -t audit-agent-backend -f Dockerfile.backend.dev .
```

then run the following command to run the server:
```bash
docker run -p 8000:8000 audit-agent-backend
```

### Run the Linters

```bash
pre-commit install
pre-commit run --all-files
```

### Run the Tests

To run the test suite (Make sure you have launched the local development server):

```bash
pytest backend/tests/ -v
```

To run the test setup environment only (Add repos as needed into `repo_samples.py` file):
```bash
pytest backend/tests/setup_environment/test_setup_environment.py -v
```

To run the hypothesis tests only:

```bash
pytest backend/tests/test_schemathesis.py -v
```

To run tests with coverage:

```bash
pytest backend/tests/ -v --cov=backend
```

To generate a coverage report:

```bash
pytest backend/tests/ -v --cov=backend --cov-report=html
```

### Run Stripe:

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

## Backend Structure

```python
backend/
├── api/                 # API Layer organized by features
│   └── v1/              # API Version 1
│       ├── agentic/     # Agentic endpoints
│       ├── audit_agent/ # Audit Agent endpoints
│       ├── auth/        # Authentication endpoints
│       ├── common/      # Common API utilities
│       ├── detectors/   # Detectors endpoints
│       ├── github/      # GitHub integration endpoints
│       ├── payments/    # Payment processing endpoints
│       ├── scans/       # Scan management endpoints
│       └── utilities/   # Utility endpoints
│
├── core/                # Core Business Logic
│   ├── db/              # Database layer and data access
│   ├── llm/             # LLM integration
│   ├── models/          # Data models
│   ├── schemas/         # Pydantic schemas
│   └── utils/           # Shared utility functions
│
├── config/              # Configuration management
│
├── tests/               # Test suite
│   ├── api/             # API tests
│   └── core/            # Core logic tests
│
└── main.py              # Application entry point

Key Files:
├── requirements.txt     # Python dependencies
├── setup.cfg            # Project configuration
├── Dockerfile.*         # Docker configurations
└── .env                 # Environment variables
```

## API Endpoints

> You can access the API endpoints and their descriptions using the following URLs: 
> - development: http://localhost:8000/docs
> - development: http://localhost:8000/redoc
> - staging: http://api.auditagent.dev/docs
> - staging: http://api.auditagent.dev/redoc

### Authentication Endpoints

<details>
<summary>GET /api/v1/auth/github-login</summary>

Initiates the GitHub OAuth flow for user authentication.

**Response:** Redirects to GitHub for authorization and installation of the app.
</details>

<details>
<summary>GET /api/v1/auth/github-callback</summary>

Handles the callback from GitHub after successful authentication.

**Response:** Sets session/JWT token and redirects to the main application.
</details>

<details>
<summary>GET /api/v1/auth/me</summary>

Retrieves the current authenticated user's information.

**Response:**
```json
{
  "username": "string",
  "email": "EmailStr",
  "githubId": "string",
  "avatarUrl": "string",
  "name": "string",
  "installationId": ["integer"],
  "subscription": {
    "isActive": "boolean",
    "type": "string",
    "credits": "integer",
    "monthlyCredits": "integer",
    "expiresAt": "Datetime",
    "lastRenewalAt": "Datetime"
  }
}
```
</details>

<details>
<summary>POST /api/v1/auth/logout</summary>

Logs out the current user.

**Response:** Clears session/JWT token and returns success message.
</details>

### GitHub Integration Endpoints

<details>
<summary>GET /api/v1/github/organizations</summary>

Retrieves the list of organizations the user has added the Github app to.

**Response:** Array of organization objects.
</details>

<details>
<summary>GET /api/v1/github/repositories/{owner}</summary>

Retrieves the list of allowed repositories for a given owner (user or organization).

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

<details>
<summary>GET /api/v1/github/validate-repo-url</summary>

Validates the provided GitHub repository URL and checks if the user has access to it.

**Parameters:**
- `repo_url`: Full URL of the GitHub repository (query parameter)

**Response:**
```json
{
  "success": true,
  "data": {
    "repo_name": "string",
    "owner": "string",
    "default_branch": "string",
    "repo_url": "string",
    "repo_full_name": "string"
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
<summary>GET /api/v1/global-stats</summary>

Retrieves the global statistics for the platform.

**Response:**
```json
{
	"success": "boolean",
	"data": {
		"total_scans": "number",
		"total_paid_scans": {
      "total": "number",
      "regular_paid": "number",
      "discounted": "number",
      "free": "number"
    },
		"total_unpaid_scans": "number",
    "total_failed_scans": "number",
		"total_findings": "number",
		"total_lines_of_code": "number",
		"scan_statuses": {
			"pending": "number",
			"in_progress": "number",
			"completed": "number",
			"failed": "number"
		}
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
  "lastLoginAt": "Datetime",
  "installationId": [integer],
  "token_version": "integer",
  "subscription": {
    "isActive": "boolean",
    "type": "string",
    "credits": "integer",
    "monthlyCredits": "integer",
    "expiresAt": "Datetime",
    "lastRenewalAt": "Datetime"
  }
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
  "discount_applied": "boolean",
  "total_findings": "number",
  "createdAt": "Datetime",
  "updatedAt": "Datetime",
  "detectors": [{"key": "string", "value": "boolean"}],
  "progress": "number",
  "completed_detectors": "number",
  "total_detectors": "number"
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
  "amount": "number",
  "createdAt": "Datetime",
  "currency": "string",
  "event_id": "string",
  "payment_type": "PaymentType",
  "scan_id": "ObjectId",
  "status": "PaymentStatus",
  "stripeSessionId": "string",
  "updatedAt": "Datetime",
  "user_id": "ObjectId"
}
```



## Profiles

<details>
<summary>Default 1</summary>

| Audit ID   | Category    | Tokens    | Total findings |
|------------|-------------|-----------|----------------|
| NM0070     | NFT-Gaming  | 10,625    | 17             |
| NM0081     | Utility     | 9,858     | 11             |
| NM0108     | DeFi        | 4,102     | 9              |
| NM0227     | DeFi        | 15,905    | 12             |
| **Total**  |             | **40,490**| **49**         |
</details>



<details>
<summary>Default 2</summary>

| Audit ID   | Category    | Tokens    | Total findings |
|------------|-------------|-----------|----------------|
| NM0062     | NFT-Gaming  | 4,480     | 14             |
| NM0074     | DeFi        | 22,813    | 14             |
| NM0225     | NFT-Gaming  | 15905     | 24             |
| **Total**  |             | **43,198**| **52**         |
</details>


<!-- <details>
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
    <li>NM0073: Tokens Input: 6,237</li>
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
</details> -->


