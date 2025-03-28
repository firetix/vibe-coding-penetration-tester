#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== VibePenTester Vercel Deployment Script ===${NC}\n"

# Check for Vercel CLI
if ! command -v vercel &> /dev/null; then
    echo -e "${YELLOW}Vercel CLI not found. Installing...${NC}"
    npm install -g vercel
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}Created .env file. Please edit it to add your API keys.${NC}"
    echo -e "You can do this now by running: ${BLUE}nano .env${NC}"
    read -p "Press Enter when you've updated your API keys..." 
fi

# Make sure requirements-vercel.txt exists
if [ ! -f requirements-vercel.txt ]; then
    echo -e "${RED}Error: requirements-vercel.txt not found.${NC}"
    exit 1
fi

# Make sure vercel.json exists
if [ ! -f vercel.json ]; then
    echo -e "${RED}Error: vercel.json not found.${NC}"
    exit 1
fi

echo -e "\n${GREEN}Ready to deploy to Vercel!${NC}"
echo -e "This script will help you deploy the VibePenTester to Vercel."
echo -e "You will be prompted to log in to Vercel if you haven't already."
echo -e "\n${YELLOW}Deployment options:${NC}"
echo -e "1) Default settings (recommended)"
echo -e "2) Custom settings (for advanced users)"

read -p "Choose an option (1/2): " deploy_option

case $deploy_option in
    1)
        echo -e "\n${BLUE}Deploying with default settings...${NC}"
        # Set Vercel flag explicitly to make sure the app detects Vercel environment
        vercel env add VERCEL 1
        vercel env add VERCEL_ENV production
        # Ensure all dependencies are installed
        echo -e "${YELLOW}Checking requirements-vercel.txt for all necessary packages...${NC}"
        if ! grep -q -i "flask-cors" requirements-vercel.txt && ! grep -q "Flask-CORS" requirements-vercel.txt; then
            echo -e "${RED}Warning: Flask-CORS not found in requirements-vercel.txt. Adding it...${NC}"
            echo "Flask-CORS>=4.0.0" >> requirements-vercel.txt
        fi
        vercel --prod
        ;;
    2)
        echo -e "\n${BLUE}Deploying with custom settings...${NC}"
        echo -e "${YELLOW}Note: When prompted for the build command, enter:${NC} pip install -r requirements-vercel.txt"
        echo -e "${YELLOW}Note: When prompted for environment variables, add your API keys.${NC}"
        
        # Set Vercel flag explicitly to make sure the app detects Vercel environment
        vercel env add VERCEL 1
        vercel env add VERCEL_ENV production
        
        # Ensure all dependencies are installed
        echo -e "${YELLOW}Checking requirements-vercel.txt for all necessary packages...${NC}"
        if ! grep -q -i "flask-cors" requirements-vercel.txt && ! grep -q "Flask-CORS" requirements-vercel.txt; then
            echo -e "${RED}Warning: Flask-CORS not found in requirements-vercel.txt. Adding it...${NC}"
            echo "Flask-CORS>=4.0.0" >> requirements-vercel.txt
        fi
        
        vercel
        ;;
    *)
        echo -e "${RED}Invalid option. Exiting.${NC}"
        exit 1
        ;;
esac

echo -e "\n${GREEN}Deployment initiated!${NC}"
echo -e "Once deployment is complete, you can access your application at the URL provided by Vercel."
echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "1) Set up your API keys in the Vercel dashboard if you haven't already"
echo -e "2) Visit your deployment URL to test the application"
echo -e "3) Check the Analytics tab in your Vercel dashboard to see visitor data"

echo -e "\n${BLUE}Thank you for using VibePenTester!${NC}" 