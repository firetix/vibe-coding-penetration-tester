# 🚀 Heroku Docker Deployment - Vulnerability Intelligence MCP Server

## 🎯 **What You're Deploying**

A complete **Vulnerability Intelligence MCP Server** with 7 powerful tools:
1. **CVE Details Lookup** - Comprehensive vulnerability information
2. **EPSS Score Analysis** - Exploitation probability prediction
3. **CVSS Score Calculator** - Severity score calculation  
4. **Vulnerability Search** - Advanced threat discovery
5. **Exploit Availability** - Public exploit intelligence
6. **Timeline Analysis** - Patch status and timeline
7. **VEX Status Checker** - Product-specific vulnerability status

## ✅ **Pre-Deployment Checklist**

Your project is **deployment-ready** with:
- ✅ `Dockerfile` - Container configuration
- ✅ `heroku.yml` - Heroku Docker build
- ✅ `app.json` - One-click deploy config
- ✅ All 7 vulnerability tools implemented
- ✅ Test suite in `tests/` directory
- ✅ SSE transport for web access

## 🚀 **Deployment Steps**

### **Step 1: Prerequisites**

```bash
# Install Heroku CLI
# macOS
brew tap heroku/brew && brew install heroku

# Windows (download from heroku.com/cli)
# Linux
curl https://cli-assets.heroku.com/install.sh | sh

# Login to Heroku
heroku login
```

### **Step 2: Deploy with Heroku CLI**

```bash
# Clone your repository (if not already local)
git clone <your-repo-url>
cd mcp-server-heroku

# Create Heroku app
heroku create your-vuln-intel-server

# Set stack to container for Docker deployment
heroku stack:set container -a your-vuln-intel-server

# Deploy the app
git push heroku main

# View deployment logs
heroku logs --tail -a your-vuln-intel-server
```

### **Step 3: Verify Deployment**

```bash
# Check app status
heroku ps -a your-vuln-intel-server

# Test SSE endpoint
curl -i https://your-vuln-intel-server.herokuapp.com/sse

# Open app in browser
heroku open -a your-vuln-intel-server
```

## 🧪 **Testing Your Deployed Server**

### **Quick Health Check**

```bash
# Test the server endpoint
curl -H "Accept: text/event-stream" \
     -H "Cache-Control: no-cache" \
     https://your-vuln-intel-server.herokuapp.com/sse
```

Expected response:
```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
```

### **Test Vulnerability Intelligence Tools**

You can test the deployed server using the test suite:

```bash
# Run comprehensive test suite against deployed server
cd tests
python test_vulnerability_intelligence.py

# Run story-based demo
python test_all_tools.py

# Test individual tools
python test_epss.py    # EPSS scores
python test_cvss.py    # CVSS calculator
python test_exploit.py # Exploit availability
```

## 🔧 **Configuration**

### **Environment Variables**

Your app comes pre-configured with:

```bash
# View current config
heroku config -a your-vuln-intel-server

# Set custom config (if needed)
heroku config:set DEBUG=true -a your-vuln-intel-server
heroku config:set MCP_USER_AGENT="Custom Agent" -a your-vuln-intel-server
```

### **Default Configuration**
- **Port**: Automatically set by Heroku (`$PORT`)
- **Host**: `0.0.0.0` (binds to all interfaces)
- **Transport**: SSE (Server-Sent Events)
- **Stack**: Container (Docker)

## 🎯 **Using with Cursor IDE**

### **Configure MCP Server in Cursor**

1. Open **Cursor Settings** → **Features** 
2. Scroll to **"MCP Servers"**
3. Click **"Add new MCP server"**
4. Configure:
   - **Name**: `Vulnerability Intelligence Server`
   - **Type**: `sse`
   - **URL**: `https://your-vuln-intel-server.herokuapp.com/sse`

### **Test Commands in Cursor**

```bash
# CVE Analysis
"Analyze CVE-2021-44228 and give me EPSS score, CVSS breakdown, and exploit availability"

# Risk Prioritization  
"Search for Apache vulnerabilities with HIGH severity from the last 6 months"

# CVSS Calculation
"Calculate CVSS score for vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Timeline Analysis
"Get vulnerability timeline for CVE-2021-44228 including patch status"

# VEX Status
"Check VEX status for CVE-2021-44228 on Apache HTTP Server"
```

## 📊 **Monitoring & Troubleshooting**

### **View Logs**
```bash
# Real-time logs
heroku logs --tail -a your-vuln-intel-server

# Last 1000 lines
heroku logs --num 1000 -a your-vuln-intel-server

# Filter for errors
heroku logs --tail -a your-vuln-intel-server | grep ERROR
```

### **Common Issues & Solutions**

#### **🔴 Build Failures**
```bash
# Check build logs
heroku logs --tail -a your-vuln-intel-server

# Test Docker build locally
docker build -t test-vuln-intel .
docker run -p 8000:8000 test-vuln-intel
```

#### **🔴 App Crashes**
```bash
# Restart the app
heroku restart -a your-vuln-intel-server

# Check dyno status
heroku ps -a your-vuln-intel-server

# Scale dynos if needed
heroku ps:scale web=1 -a your-vuln-intel-server
```

#### **🔴 API Rate Limiting**
- NVD API has rate limits (~50 requests per 30 seconds)
- FIRST.org EPSS API is generally more lenient
- Consider implementing caching for production use

### **Performance Optimization**

#### **Dyno Types**
- **Eco ($5/month)**: Good for development/testing
- **Basic ($7/month)**: Better for light production use  
- **Standard ($25/month)**: Full production with metrics

```bash
# Upgrade dyno type
heroku ps:type standard -a your-vuln-intel-server
```

#### **Resource Usage**
- **Memory**: ~100-200MB typical usage
- **CPU**: Low baseline, spikes during API calls
- **Network**: Moderate (external API calls)

## 🔒 **Security Considerations**

### **API Security**
- All external API calls use HTTPS
- No API keys required for public endpoints
- Rate limiting handled gracefully

### **Data Privacy**
- Stateless server (no data persistence)
- No user data collection
- All vulnerability data is public information

### **Network Security**
```bash
# Force HTTPS redirects (recommended)
heroku config:set FORCE_HTTPS=true -a your-vuln-intel-server
```

## 🎬 **Demo & Presentation**

### **Live Demo URLs**
```bash
# Your deployed server
https://your-vuln-intel-server.herokuapp.com

# SSE endpoint for MCP
https://your-vuln-intel-server.herokuapp.com/sse

# Health check
https://your-vuln-intel-server.herokuapp.com/health
```

### **Demo Script**
1. **Show server status** in Heroku dashboard
2. **Configure Cursor** with your server URL
3. **Run test commands** showing each tool
4. **Demonstrate workflow** using the test suite
5. **Show real-time logs** during API calls

## 📈 **Scaling & Production**

### **Custom Domain**
```bash
# Add custom domain
heroku domains:add vuln-intel.your-company.com -a your-vuln-intel-server

# Configure DNS
# Add CNAME record: vuln-intel -> your-vuln-intel-server.herokuapp.com
```

### **SSL Certificate**
```bash
# Enable automatic SSL
heroku certs:auto:enable -a your-vuln-intel-server
```

### **Monitoring Add-ons**
```bash
# Add logging
heroku addons:create papertrail -a your-vuln-intel-server

# Add metrics  
heroku addons:create librato -a your-vuln-intel-server
```

## 🎉 **Success Checklist**

✅ **Deployment Complete**
- [ ] App deployed to Heroku successfully
- [ ] SSE endpoint responding
- [ ] All 7 tools accessible via MCP
- [ ] Configured in Cursor IDE
- [ ] Test suite passes against deployed server

✅ **Production Ready**
- [ ] Custom domain configured (optional)
- [ ] SSL certificate enabled
- [ ] Monitoring set up
- [ ] Error tracking configured
- [ ] Performance baseline established

---

## 🚀 **Quick Deploy Commands**

```bash
# Complete deployment in 3 commands
heroku create your-vuln-intel-server
heroku stack:set container -a your-vuln-intel-server  
git push heroku main

# Test deployment
curl -i https://your-vuln-intel-server.herokuapp.com/sse
```

**🎯 Your Vulnerability Intelligence MCP Server is now live on Heroku!**

Use it in Cursor IDE to transform your security vulnerability analysis workflow from hours of manual research to minutes of automated intelligence gathering. 