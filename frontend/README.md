<div align="center">
<h1><strong> <span style="color:#8660f2"> Audit</span> Agent UI </strong></h1>
</div>

## Table of Contents

- [Introduction](#introduction)
- [Technologies Used](#technologies-used)
- [Getting Started](#getting-started)
  - [Install dependencies](#install-dependencies)
  - [Run the development server](#run-the-development-server)
- [License](#license)

## Introduction

AgentAudit UI is the frontend component of the Yokai AuditAgent, a powerful tool designed for smart contract auditing and security analysis. This user interface provides an intuitive and efficient way for developers and auditors to interact with the Yokai AuditAgent's core functionality.

Key features of the Agent Audit UI include:

1. User-friendly dashboard for managing and initiating smart contract audits
2. Real-time display of audit progress and results
3. Detailed vulnerability reports with severity classifications
4. Integration with GitHub for seamless code repository analysis
5. Customizable audit parameters and settings
6. Secure user authentication and project management

The Agent Audit UI is built with modern web technologies to ensure a responsive, accessible, and performant experience across devices. It serves as the primary interface for users to leverage the advanced capabilities of the Yokai AuditAgent, streamlining the process of identifying and addressing potential vulnerabilities in smart contract code.

## Technologies Used

- [Next.js 14](https://nextjs.org/docs/getting-started)
- [NextUI v2](https://nextui.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Tailwind Variants](https://tailwind-variants.org)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)

## Getting Started

### Configure environment variables

If you are coming from the parent [readme](../README.md) and want to run both frontend and backend together, you just need to configure the environment variables below. No need to run the frontend separately

1. NEXT_PUBLIC_API_URL
2. NEXT_PUBLIC_GITHUB_APP_URL
3. X_API_KEY - Set your own API key
   
Copy the `.env.example` file to `.env` and set the following environment variables:

```javascript
# Public Variables
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_GITHUB_APP_URL=https://github.com/apps/<app-name>/installations/new

# Private Variables
X_API_KEY=<your-api-key>
```
### How to run the frontend separately

#### Install dependencies

You can use one of them `npm`, `yarn`, `pnpm`, `bun`, Example using `npm`:

```bash
cd frontend
npm install
```

#### Run the development server

```bash
npm run dev
```

#### Setup pnpm (optional)

If you are using `pnpm`, you need to add the following code to your `.npmrc` file:

```bash
public-hoist-pattern[]=*@nextui-org/*
```

After modifying the `.npmrc` file, you need to run `pnpm install` again to ensure that the dependencies are installed correctly.

## License

Licensed under the [MIT license](https://github.com/nextui-org/next-app-template/blob/main/LICENSE).
