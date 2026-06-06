# Heroku Deployment Guide for MCP Vulnerability Checker Server

## 🚀 Prerequisites

Before deploying to Heroku, ensure you have:

1. **Heroku Account**: Sign up at [heroku.com](https://heroku.com)
2. **Heroku CLI**: Install from [devcenter.heroku.com/articles/heroku-cli](https://devcenter.heroku.com/articles/heroku-cli)
3. **Git Repository**: Your code should be in a Git repository

## 📋 Pre-Deployment Checklist

### ✅ Files Ready for Deployment

All necessary files are already configured:

- `✅ Dockerfile` - Container configuration
- `✅ heroku.yml` - Heroku build configuration  
- `✅ app.json` - App metadata and environment variables
- `✅ pyproject.toml` - Python package configuration with entry point
- `✅ requirements files` - Dependencies managed by pyproject.toml

### ✅ Entry Points Configured

- **Script entry point**: `mcp-simple-tool` → `mcp_simple_tool.server:main`
- **Module entry point**: `python -m mcp_simple_tool.server`
- **Container command**: `mcp-simple-tool --transport sse --port $PORT`

### ✅ Environment Variables

Default environment variables in `app.json`:
- `MCP_SERVER_PORT`: 8000
- `MCP_SERVER_HOST`: 0.0.0.0  
- `DEBUG`: false
- `MCP_USER_AGENT`: Custom user agent string

## 🚀 Deployment Methods

### Method 1: One-Click Deploy (Recommended)

1. Click the "Deploy to Heroku" button in the README
2. Configure app name and environment variables
3. Click "Deploy app"
4. Wait for build to complete (~3-5 minutes)

### Method 2: Heroku CLI Deploy

1. **Login to Heroku**:
   ```bash
   heroku login
   ```

2. **Create Heroku app**:
   ```bash
   heroku create your-mcp-server-name
   ```

3. **Set stack to container** (for Docker deployment):
   ```bash
   heroku stack:set container -a your-mcp-server-name
   ```

4. **Deploy the app**:
   ```bash
   git push heroku main
   ```

5. **View logs**:
   ```bash
   heroku logs --tail -a your-mcp-server-name
   ```

### Method 3: GitHub Integration

1. Connect your GitHub repository to Heroku
2. Enable automatic deployments from main branch
3. Manual deploy or push to trigger deployment

## 🔧 Configuration After Deployment

### 1. Verify Deployment

Check that your app is running:

```bash
# Check app status
heroku ps -a your-mcp-server-name

# Check logs
heroku logs --tail -a your-mcp-server-name

# Test the endpoint
curl -i https://your-mcp-server-name.herokuapp.com/sse
```

### 2. Get Your App URL

Your MCP server will be available at:
- **Base URL**: `https://your-mcp-server-name.herokuapp.com`
- **SSE Endpoint**: `https://your-mcp-server-name.herokuapp.com/sse`

### 3. Configure Cursor IDE

1. Open Cursor Settings → Features
2. Scroll to "MCP Servers" 
3. Click "Add new MCP server"
4. Fill in:
   - **Name**: "MCP Vulnerability Checker"
   - **Type**: "sse" 
   - **URL**: `https://your-mcp-server-name.herokuapp.com/sse`

## 🧪 Testing Your Deployment

### 1. Health Check

Test basic connectivity:
```bash
curl -i https://your-mcp-server-name.herokuapp.com/sse
```

Expected response: Connection established with SSE headers.

### 2. Tool Testing in Cursor

Try these commands in Cursor after configuration:

1. **CVE Lookup**:
   - "Look up CVE-2021-44228"
   - Should return detailed Log4Shell vulnerability information

2. **Package Vulnerability Check**:
   - "Check the 'requests' Python package for vulnerabilities"
   - Should return security report with known vulnerabilities


## 🔍 Troubleshooting

### Common Issues

1. **Build Failures**:
   ```bash
   # Check build logs
   heroku logs --tail -a your-app-name
   
   # Check if container builds locally
   docker build -t test-mcp .
   docker run -p 8000:8000 test-mcp
   ```

2. **App Crashes**:
   ```bash
   # Check runtime logs
   heroku logs --tail -a your-app-name
   
   # Restart the app
   heroku restart -a your-app-name
   ```

3. **Port Binding Issues**:
   - Ensure Dockerfile exposes port 8000
   - Heroku automatically sets `$PORT` environment variable
   - App should bind to `0.0.0.0:$PORT`

4. **Import Errors**:
   - Verify pyproject.toml entry points
   - Check that all tool modules are properly imported
   - Test locally with `python -m mcp_simple_tool.server`

### Debug Commands

```bash
# View app configuration
heroku config -a your-app-name

# Access app shell (for debugging)
heroku run bash -a your-app-name

# Scale app (if needed)
heroku ps:scale web=1 -a your-app-name

# View app info
heroku info -a your-app-name
```

## 🎯 Performance Optimization

### Heroku Dyno Types

- **Free/Eco**: Good for testing (sleeps after 30 min inactivity)
- **Basic**: Better for development (no sleeping)
- **Standard**: Production-ready with metrics

### Memory and CPU

The MCP server is lightweight and should run well on basic dynos:
- **Memory**: ~50-100MB typical usage
- **CPU**: Low usage except during API calls
- **Network**: Moderate (API calls to NVD, OSV, PyPI)

## 🔒 Security Considerations

### Environment Variables

Never commit sensitive data:
- Use Heroku config vars for API keys
- Set via CLI: `heroku config:set API_KEY=value -a your-app`

### Network Security

- All external API calls use HTTPS
- No sensitive data is stored on the server
- Stateless design - no user data persistence

## 📈 Monitoring

### Basic Monitoring

```bash
# View real-time logs
heroku logs --tail -a your-app-name

# Check dyno metrics
heroku ps -a your-app-name

# View app events
heroku releases -a your-app-name
```

### Advanced Monitoring

Consider adding:
- Heroku metrics add-ons
- Application performance monitoring (APM)
- Log aggregation services

## 🎉 Next Steps

After successful deployment:

1. **Test all tools** thoroughly in Cursor
2. **Monitor logs** for any issues
3. **Share your app URL** with your team
4. **Consider upgrading** to paid dyno for production use
5. **Add custom domain** if needed
6. **Set up monitoring** and alerts

## 📞 Support

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Review Heroku logs for error details
3. Test components individually with the test suite
4. Ensure all dependencies are properly specified

Your MCP Vulnerability Checker Server should now be running on Heroku! 🎉 