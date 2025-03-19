from typing import Dict, List, Any, Set
import urllib.parse
import random
from playwright.sync_api import Page

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import BaseAgent
from utils.logger import get_logger
from utils.list_helper import load_subdomains, load_fuzz_directories

class DiscoverySwarm:
    """A swarm of agents for discovering URLs and attack surfaces."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner, config: Dict[str, Any]):
        self.llm_provider = llm_provider
        self.scanner = scanner
        self.config = config
        self.logger = get_logger()
        
        # Create specialized discovery agents
        self.agents = {
            "crawler": CrawlerAgent(llm_provider, scanner),
            "directory": DirectoryBruteforceAgent(llm_provider, scanner),
            "subdomain": SubdomainEnumerationAgent(llm_provider, scanner)
        }
    
    def discover_urls(self, base_url: str, scope: str = "url", subdomains: bool = False) -> Set[str]:
        """Discover additional URLs based on the base URL and scope setting."""
        discovered_urls = set([base_url])
        
        # Always run crawler for any scope
        self.logger.info(f"Starting crawler for {base_url}")
        crawled_urls = self.agents["crawler"].crawl(base_url)
        discovered_urls.update(crawled_urls)
        
        # For domain or subdomain scope, try to discover additional content
        if scope in ["domain", "subdomain"]:
            self.logger.info(f"Starting directory bruteforce for {base_url}")
            directory_urls = self.agents["directory"].discover_directories(base_url)
            discovered_urls.update(directory_urls)
        
        # Only for subdomain scope, enumerate subdomains
        if subdomains:
            self.logger.info(f"Starting subdomain enumeration for {base_url}")
            parsed_url = urllib.parse.urlparse(base_url)
            domain = parsed_url.netloc
            subdomain_urls = self.agents["subdomain"].enumerate_subdomains(domain)
            discovered_urls.update(subdomain_urls)
        
        return discovered_urls

class CrawlerAgent(BaseAgent):
    """Agent for crawling websites to discover URLs."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "crawl_website",
                    "description": "Crawl a website to discover links and content",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL to start crawling from"
                            },
                            "max_depth": {
                                "type": "integer",
                                "description": "Maximum crawling depth"
                            },
                            "max_pages": {
                                "type": "integer",
                                "description": "Maximum number of pages to crawl"
                            }
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "extract_links",
                    "description": "Extract links from a web page",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL of the page to extract links from"
                            }
                        },
                        "required": ["url"]
                    }
                }
            }
        ]
        super().__init__("CrawlerAgent", "crawler", llm_provider, tools)
        self.scanner = scanner
    
    def crawl(self, url: str, max_depth: int = 2, max_pages: int = 20) -> Set[str]:
        """Crawl a website starting from the given URL."""
        system_prompt = """
        You are a web crawler expert. Your task is to systematically explore websites to discover URLs and content.
        Focus on finding all accessible pages, API endpoints, and resources.
        Prioritize interesting or security-relevant paths like admin interfaces, login pages, and file upload functions.
        Be thorough but respect the provided depth and page limits.
        """
        
        input_data = {
            "content": f"Crawl the website starting at: {url}\nMax depth: {max_depth}\nMax pages: {max_pages}"
        }
        
        response = self.think(input_data, system_prompt)
        discovered_urls = set()
        
        if response["tool_calls"]:
            for tool_call in response["tool_calls"]:
                tool_result = self.execute_tool(tool_call)
                
                if isinstance(tool_result, dict) and "urls" in tool_result:
                    discovered_urls.update(tool_result["urls"])
        
        return discovered_urls

class DirectoryBruteforceAgent(BaseAgent):
    """Agent for discovering directories and files through bruteforcing."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "brute_force_directories",
                    "description": "Brute force directories and files on a website",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "base_url": {
                                "type": "string",
                                "description": "Base URL to brute force"
                            },
                            "wordlist": {
                                "type": "string",
                                "description": "Name of wordlist to use (common, medium, or large)"
                            },
                            "extensions": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                },
                                "description": "File extensions to check"
                            }
                        },
                        "required": ["base_url"]
                    }
                }
            }
        ]
        super().__init__("DirectoryBruteforceAgent", "directory_bruteforce", llm_provider, tools)
        self.scanner = scanner
    
    def discover_directories(self, base_url: str) -> Set[str]:
        """Discover directories and files through bruteforcing."""
        system_prompt = """
        You are a directory bruteforcing expert. Your task is to discover hidden or unlinked directories and files on websites.
        Use common naming patterns and wordlists to efficiently find resources.
        Focus on potentially sensitive files and directories that might expose vulnerabilities.
        Be thorough but avoid generating excessive traffic that might trigger security alarms.
        """
        
        input_data = {
            "content": f"Discover directories and files on: {base_url}\nUse a common wordlist with standard web extensions."
        }
        
        response = self.think(input_data, system_prompt)
        discovered_urls = set()
        
        if response["tool_calls"]:
            for tool_call in response["tool_calls"]:
                # Import the brute_force_directories tool
                from tools.scanning_tools import brute_force_directories
                
                # Get the tool name and arguments
                tool_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]
                
                if tool_name == "brute_force_directories":
                    base_url = args.get("base_url", "")
                    wordlist = args.get("wordlist", "common")
                    extensions = args.get("extensions", None)
                    
                    # Call the actual tool function
                    tool_result = brute_force_directories(base_url, wordlist, extensions)
                else:
                    tool_result = self.execute_tool(tool_call)
                
                if isinstance(tool_result, dict) and "urls" in tool_result:
                    discovered_urls.update(tool_result["urls"])
        
        return discovered_urls

class SubdomainEnumerationAgent(BaseAgent):
    """Agent for discovering subdomains."""
    
    def __init__(self, llm_provider: LLMProvider, scanner: Scanner):
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "enumerate_subdomains",
                    "description": "Enumerate subdomains for a given domain",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain to enumerate subdomains for"
                            },
                            "techniques": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["wordlist", "certificate", "dns"]
                                },
                                "description": "Techniques to use for subdomain enumeration"
                            }
                        },
                        "required": ["domain"]
                    }
                }
            }
        ]
        super().__init__("SubdomainEnumerationAgent", "subdomain_enumeration", llm_provider, tools)
        self.scanner = scanner
    
    def enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate subdomains for the given domain."""
        system_prompt = """
        You are a subdomain enumeration expert. Your task is to discover subdomains for a given domain.
        Use various techniques including wordlist bruteforcing, certificate transparency logs, and DNS records.
        Focus on finding as many valid subdomains as possible that might expand the attack surface.
        Be thorough but avoid techniques that might trigger security alarms.
        """
        
        input_data = {
            "content": f"Enumerate subdomains for: {domain}\nUse wordlist, certificate, and DNS techniques."
        }
        
        response = self.think(input_data, system_prompt)
        discovered_urls = set()
        
        if response["tool_calls"]:
            for tool_call in response["tool_calls"]:
                # Import the enumerate_subdomains tool
                from tools.scanning_tools import enumerate_subdomains
                
                # Get the tool name and arguments
                tool_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]
                
                if tool_name == "enumerate_subdomains":
                    domain_name = args.get("domain", "")
                    techniques = args.get("techniques", ["wordlist", "certificate", "dns"])
                    
                    # Call the actual tool function
                    tool_result = enumerate_subdomains(domain_name, techniques)
                else:
                    tool_result = self.execute_tool(tool_call)
                
                if isinstance(tool_result, dict) and "subdomains" in tool_result:
                    # Convert subdomains to full URLs
                    for subdomain in tool_result["subdomains"]:
                        discovered_urls.add(f"https://{subdomain}")
        
        return discovered_urls
