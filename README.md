<div align="center">
<h1><strong> <span style="color:#8660f2"> Audit</span> Agent </strong></h1>
</div>

<br >

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction

Yokai Audit Agent is an advanced smart contract auditing tool that leverages AI to detect vulnerabilities and provide comprehensive security analysis. Our platform offers automated scanning, detailed reporting, and expert insights to ensure the integrity and security of blockchain projects.

## Features

- AI-powered smart contract vulnerability detection
- GitHub integration for seamless repository scanning
- Detailed vulnerability reports with severity classifications
- Context-aware analysis for more accurate results
- Payment integration for full scan access

## Project Structure

This project is divided into two main components:

- [Frontend](./frontend/README.md): The user interface for interacting with the Yokai Audit Agent.
- [Backend](./backend/README.md): The API and core functionality of the Yokai Audit Agent.

For specific information about each component, please refer to their respective README files.

## Getting Started

To get started with Yokai Audit Agent, follow these steps:

### 1. Clone the repository

```bash
git clone https://github.com/NethermindEth/ai-auditor.git
```

### 2. Configure all environment variables

#### In the frontend folder

```bash
# Public Variables
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_GITHUB_APP_URL=https://github.com/apps/<app-name>/installations/new

# Private Variables
X_API_KEY=<your-api-key>

```

#### In the backend folder

```bash
ENVIRONMENT=development
FRONTEND_URL=http://localhost:3000
BASE_URL=http://localhost:8000
COOKIE_DOMAIN=localhost
...
```

### 3. Start docker compose

#### Local Development

```bash
docker-compose up --build

# To reinstall the dependencies, run the following command first
docker-compose down --volumes
```

#### Local Staging Deployment (TESTING THE DOCKERFILE ONLY)

```bash
docker-compose -f docker-compose.staging.yml up --build
```

### 4. Run the application

For more infos, refers the the different READMEs
- Set up the backend (see [Backend README](./backend/README.md))
- Set up the frontend (see [Frontend README](./frontend/README.md))

## Contributing

We welcome contributions to Yokai Audit Agent. Please read our contributing guidelines before submitting pull requests.

## License

[Specify your license here]

## Contact

For any inquiries, please contact [Your Contact Information].