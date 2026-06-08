# 🚀 Heroku TIP MCP Server Deployment Guide


## 🔧 Pre-Deployment Steps

### 1. Verify Heroku CLI Setup

```bash
# Login to Heroku (if not already)
heroku login

# Verify your app exists
heroku apps:info vulnerability-intelligence-mcp-server

# Set the stack to container (required for Docker deployment)
heroku stack:set container -a vulnerability-intelligence-mcp-server
```

### 2. Add Heroku Remote to Your Git Repository

```bash
# Navigate to your local repository
cd /path/to/your/tip-mcp-heroku

# Add Heroku as a remote
heroku git:remote -a vulnerability-intelligence-mcp-server

# Verify remotes
git remote -v
```
## 🚀 Deployment Commands

### Deploy to Heroku

```bash
# Make sure you're on the main/master branch
git branch

# Push to Heroku (this will trigger the build)
git push heroku main
# OR if your default branch is master:
# git push heroku master
```

### Monitor the Deployment

```bash
# Watch the build logs in real-time
heroku logs --tail -a vulnerability-intelligence-mcp-server

# Check app status
heroku ps -a vulnerability-intelligence-mcp-server

# View configuration
heroku config -a vulnerability-intelligence-mcp-server
```

## ✅ Expected Deployment Process

1. **Build Phase** (~2-3 minutes):
   - Heroku will detect the `heroku.yml` file
   - Docker container will be built using the Dockerfile
   - Dependencies will be installed via `pip install -e ".[dev]"`

2. **Release Phase** (~30 seconds):
   - Container will be deployed
   - App will start with: `mcp-simple-tool --transport sse --port $PORT`

3. **App Running**:
   - Your server will be available at: `https://vulnerability-intelligence-mcp-server.herokuapp.com/sse`

## 🧪 Testing Your Deployment

### 1. Health Check

```bash
# Test the SSE endpoint
curl -i https://vulnerability-intelligence-mcp-server.herokuapp.com/sse
```

Expected response: SSE connection headers.

### 2. Configure Cursor IDE

1. Open Cursor Settings → Features
2. Scroll to "MCP Servers"
3. Click "Add new MCP server"
4. Fill in:
   - **Name**: "TIP MCP Vulnerability Checker"
   - **Type**: "sse"
   - **URL**: `https://vulnerability-intelligence-mcp-server.herokuapp.com/sse`

### 3. Test the Security Tools

Try these commands in Cursor:

1. **CVE Lookup**:
   - "Look up CVE-2021-44228"
   - Should return detailed Log4Shell vulnerability information

2. **Python Package Vulnerability Check**:
   - "Check the 'requests' Python package for vulnerabilities"
   - Should return comprehensive security report


## 🔍 Troubleshooting

### Common Issues

1. **Build Failures**:
   ```bash
   # Check detailed build logs
   heroku logs --tail -a vulnerability-intelligence-mcp-server
   
   # Check recent releases
   heroku releases -a vulnerability-intelligence-mcp-server
   ```

2. **Port Binding Issues**:
   - Heroku automatically sets `$PORT` environment variable
   - The app binds to `0.0.0.0:$PORT` as configured

3. **Import/Module Errors**:
   ```bash
   # Test locally first
   python -m mcp_simple_tool.server --help
   
   # Run the test suite
   python tests/run_tests.py
   ```

### Debug Commands

```bash
# Access the app container for debugging
heroku run bash -a vulnerability-intelligence-mcp-server

# Restart the app if needed
heroku restart -a vulnerability-intelligence-mcp-server

# View app configuration
heroku config -a vulnerability-intelligence-mcp-server

# Scale the app (if needed)
heroku ps:scale web=1 -a vulnerability-intelligence-mcp-server
```

## 🎯 Production Considerations

### Dyno Management

```bash
# Check current dyno usage
heroku ps -a vulnerability-intelligence-mcp-server

# Upgrade dyno type if needed (for better performance)
heroku ps:resize web=basic -a vulnerability-intelligence-mcp-server
```

### Environment Variables

Set any additional environment variables:
```bash
# Example: Set custom user agent for your organization

# Enable debug mode if needed
heroku config:set DEBUG=true -a vulnerability-intelligence-mcp-server
```

### Monitoring

```bash
# Set up log drains for centralized logging (if needed)
heroku drains -a vulnerability-intelligence-mcp-server

# View metrics (if on paid plan)
heroku logs --ps web -a vulnerability-intelligence-mcp-server
```

## 🎉 Ready to Deploy!

Your MCP server includes:
- **CVE Lookup**: NIST NVD vulnerability database
- **Python Package Security**: OSV vulnerability scanning  

Run these commands to deploy:

```bash
# 1. Set container stack
heroku stack:set container -a vulnerability-intelligence-mcp-server

# 2. Add Heroku remote
heroku git:remote -a vulnerability-intelligence-mcp-server

# 3. Deploy!
git push heroku main

# 4. Monitor
heroku logs --tail -a vulnerability-intelligence-mcp-server
```

Your TIP MCP Vulnerability Checker will be live at:
**https://vulnerability-intelligence-mcp-server.herokuapp.com/sse** 