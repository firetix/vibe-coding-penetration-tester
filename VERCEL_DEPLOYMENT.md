# Deploying VibePenTester to Vercel

This document provides step-by-step instructions for deploying the VibePenTester application to Vercel.

> For split-plane architecture (Vercel frontend + Railway backend), use this together with [`docs/railway-deployment.md`](docs/railway-deployment.md).

## Prerequisites

1. Create a Vercel account at [vercel.com](https://vercel.com) if you don't have one already
2. Install the Vercel CLI: `npm i -g vercel`
3. Obtain API keys for OpenAI and/or Anthropic (optional)

## Setup Steps

### 1. Prepare Your Project

Your project already contains the necessary files for Vercel deployment:
- `vercel.json` - Configuration for Vercel deployment
- `requirements-vercel.txt` - Python dependencies for Vercel

### 2. Set Up Environment Variables

1. Create a `.env` file based on the provided `.env.example`:
   ```
   cp .env.example .env
   ```

2. Fill in your actual API keys and Google Analytics Measurement ID in the `.env` file:
   ```
   OPENAI_API_KEY=sk-your-real-openai-key
   ANTHROPIC_API_KEY=sk-ant-your-real-anthropic-key
   GA_MEASUREMENT_ID=G-YOURACTUALID
   ```

3. If you're deploying a separate frontend on Vercel with backend on Railway, add these Vercel env vars:
   ```
   NEXT_PUBLIC_API_BASE_URL=https://<your-railway-api-domain>
   API_BASE_URL=https://<your-railway-api-domain>
   NEXT_PUBLIC_SUPABASE_URL=<your-supabase-url>
   NEXT_PUBLIC_SUPABASE_ANON_KEY=<your-supabase-anon-key>
   NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=<your-stripe-publishable-key>
   ```

### 3. Deploy to Vercel

#### Option 1: Using Vercel CLI

1. Login to Vercel:
   ```
   vercel login
   ```

2. Deploy the application:
   ```
   vercel
   ```

3. During deployment, Vercel will prompt you to confirm settings:
   - Set the build command to: `pip install -r requirements-vercel.txt`
   - Set the output directory to: ` ` (leave empty)
   - Add the environment variables from your `.env` file

4. Once deployed, Vercel will provide a URL for your application.

#### Option 2: Using Vercel Dashboard

1. Push your code to a GitHub repository

2. Log in to [Vercel Dashboard](https://vercel.com/dashboard)

3. Click "Add New" > "Project"

4. Import your GitHub repository

5. Configure the project:
   - Framework Preset: Other
   - Build Command: `pip install -r requirements-vercel.txt`
   - Output Directory: leave empty
   - Install Command: leave default

6. Add environment variables:
   - `OPENAI_API_KEY`: Your OpenAI API key
   - `ANTHROPIC_API_KEY`: Your Anthropic API key  

7. Click "Deploy"

### 4. Verify Deployment

1. Visit your deployed application URL provided by Vercel

2. Test the functionality by running a scan on a website

3. Check that Vercel Analytics is collecting data by visiting the Analytics tab in your Vercel project dashboard

## Troubleshooting

### Serverless Architecture Considerations

#### File System Issues

- Vercel uses a read-only file system, so our application is configured to use `/tmp` for storing logs and reports
- If you see errors related to file permissions or "Read-only file system", verify that the application is properly detecting the Vercel environment
- The environment variables `VERCEL=1` and `VERCEL_ENV=production` should be set for proper detection

#### Threading and Background Processing

- Vercel's serverless functions don't support background threads or long-running processes
- VibePenTester uses a progressive scan approach where the security testing advances incrementally through the `/status` endpoint polls rather than running in background threads
- Each API request must complete in under 10 seconds due to Vercel's timeout limits

#### State Management

- Serverless functions are stateless by design, so we store scan state in the `/tmp` directory
- The `sessions.json` file in `/tmp` maintains scan progress between function invocations
- Reports are also stored in `/tmp/vibe_pen_tester_reports` directory

#### XSS Detection Implementation

- XSS vulnerability detection has been specially adapted for serverless environments
- During scan progression (when `/status` is polled), the scanner performs real XSS testing at specific progress steps
- The application directly uses `test_xss_payload()` from security_tools.py to test for XSS vulnerabilities
- Actual XSS findings are stored in the scan state and included in the final report

### Deployment Script

We've included a convenient deployment script that handles Vercel-specific configuration:

```bash
# Run the automated deployment script
./deploy-to-vercel.sh
```

This script will:
1. Check for Vercel CLI
2. Set up necessary environment variables
3. Deploy to Vercel with proper configuration

### Other Common Issues

- If you encounter issues with Playwright on Vercel, you may need to use a [custom build step](https://vercel.com/docs/concepts/functions/edge-functions/playwright) to install browsers

- For large scans, you might encounter timeout issues as Vercel has a [maximum execution time](https://vercel.com/docs/functions/serverless-functions/runtimes#execution-timeout). Consider limiting the scan scope for the hosted version.

- Check the Vercel logs if something isn't working as expected: `vercel logs <deployment-url>`

## Additional Configuration

### Custom Domain

1. Go to your Vercel project dashboard

2. Navigate to "Settings" > "Domains"

3. Add your custom domain and follow the verification process

### Setting Up Analytics

Vercel Analytics is automatically enabled for your project. To view analytics:

1. Go to your Vercel project dashboard

2. Navigate to the "Analytics" tab

3. You'll see visitor data, performance metrics, and other insights

For more advanced analytics options, you can also integrate with other platforms through Vercel integrations. 