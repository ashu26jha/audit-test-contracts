# Yokai Audit Agent Backend

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Running the Server](#running-the-server)
- [Running Tests](#running-tests)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Roadmap](#roadmap)

## Introduction

This is the backend component of the Yokai Audit Agent, providing the core functionality for smart contract auditing, GitHub integration, and user management.

## Getting Started

### Prerequisites

- Python 3.8+
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

3. Set up environment variables (create a .env file in the backend directory):
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
{
  "id": "string",
  "username": "string",
  "email": "string",
  "githubId": "string"
}

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

### Scanning Endpoints

<details>
<summary>POST /api/v1/audit-agent</summary>

Initiates a new scan for selected smart contracts.

**Request Body:**
{
  "repositoryURL": "string",
  "contractFiles": ["string"],
  "authToken": "string (optional)"
}

**Response:**
{
  "scan_id": "UUID"
}

</details>

<details>
<summary>GET /api/v1/scans/{scan_id}</summary>

Retrieves the full results of a specific scan.

**Parameters:**
- `scan_id`: UUID of the scan (path parameter)

**Response:**
{
  "scan_id": "UUID",
  "summary": "string",
  "type": "string",
  "scan_result": [
    {
      "Issue": "string",
      "Severity": "string",
      "Contracts": ["string"],
      "Description": "string",
      "Recommendation": "string"
    }
  ]
}

</details>

<details>
<summary>GET /api/v1/scans/partial/{scan_id}</summary>

Retrieves partial results of a specific scan (limited findings).

**Parameters:**
- `scan_id`: UUID of the scan (path parameter)

**Response:** Same as full results, but with a limited number of findings.
</details>

### Miscellaneous Endpoints

<details>
<summary>GET /api/v1/health-check</summary>

Simple health check endpoint to verify API status.

**Response:**
{
  "status": "string",
  "version": "string"
}

</details>

<details>
<summary>POST /api/v1/generate-summary</summary>

Generates a summary of smart contracts.

**Request Body:**
{
  "contracts": "string"
}

**Response:**
{
  "summary": "string",
  "type": "string"
}

</details>

<details>
<summary>POST /api/v1/context-scan</summary>

Performs a context-aware scan of smart contracts.

**Request Body:**
{
  "summary": "string (optional)",
  "contracts": "string",
  "profile": "string"
}

**Response:**
{
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

</details>

## Database Schema

### Users Collection

```json
{
  "_id": "ObjectId",
  "githubId": "String",
  "username": "String",
  "email": "String",
  "avatarUrl": "String",
  "createdAt": "Date",
  "updatedAt": "Date",
  "lastLoginAt": "Date"
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
  "repositoryId": "ObjectId",
  "userId": "ObjectId",
  "status": "String",
  "startedAt": "Date",
  "completedAt": "Date",
  "contractFiles": ["String"],
  "vulnerabilities": [
    {
      "type": "String",
      "issue": "String",
      "severity": "String",
      "contracts": ["String"],
      "description": "String",
      "recommendation": "String"
    }
  ],
  "paidStatus": "Boolean",
  "createdAt": "Date",
  "updatedAt": "Date"
}
```

### Payments Collection

```json
{
  "_id": "ObjectId",
  "userId": "ObjectId",
  "scanId": "ObjectId",
  "amount": "Number",
  "currency": "String",
  "status": "String",
  "stripeSessionId": "String",
  "createdAt": "Date",
  "updatedAt": "Date"
}
```

## Roadmap

- [x] Health check endpoint/service
- [x] Context scan endpoint/service
- [x] Generate summary endpoint/service
- [ ] Critics endpoint/service
- [ ] Flatten contracts endpoint/service
- [ ] Scan restriction when not paid
- [ ] Add missing profiles
- [ ] Add test for all services