from openai import OpenAI
from typing import Dict, List, Any, Optional
import asyncio
import time

from core.llm import LLMProvider
from core.scanner import Scanner
from agents.agent_factory import create_agent_swarm
from utils.logger import get_logger
from utils.reporter import Reporter

class SwarmCoordinator:
    """Coordinates the activities of multiple specialized security testing agents operating in a swarm."""
    
    def __init__(self, url: str, model: str, provider: str, scope: str, output_dir: str, config: Dict[str, Any], 
                 openai_api_key: str = None, anthropic_api_key: str = None):
        self.url = url
        self.model = model
        self.provider = provider
        self.scope = scope
        self.output_dir = output_dir
        self.config = config
        self.logger = get_logger()
        
        self.llm_provider = LLMProvider(
            provider=provider, 
            model=model,
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key
        )
        self.scanner = Scanner()
        self.reporter = Reporter(output_dir)
        
        # Tracking variables
        self.discovered_urls = set([url])
        self.scanned_urls = set()
        self.vulnerabilities = []
    
    def run(self) -> Dict[str, Any]:
        """Execute the full security testing workflow."""
        self.logger.info(f"Starting security testing of {self.url} with {self.provider} model {self.model}")
        
        # Initialize Playwright browser
        self.scanner.start()
        
        try:
            # Process target URLs according to scope
            if self.scope in ["domain", "subdomain"]:
                self._expand_scope()
            
            # Process each URL
            for url in self.discovered_urls:
                if url in self.scanned_urls:
                    continue
                
                self.logger.info(f"Processing URL: {url}")
                results = self._process_url(url)
                self.logger.info(f"Security testing results for {url}: {len(results)} vulnerabilities found")
                
                # Print detailed debug info about the results
                if results:
                    self.logger.highlight(f"Found {len(results)} potential vulnerabilities:")
                    for idx, vuln in enumerate(results, 1):
                        self.logger.highlight(f"  Vulnerability #{idx}:")
                        self.logger.info(f"    Type: {vuln.get('vulnerability_type', 'Unknown')}")
                        self.logger.info(f"    Severity: {vuln.get('severity', 'Unknown')}")
                        self.logger.info(f"    Target: {vuln.get('target', 'Unknown')}")
                        self.logger.info(f"    Validated: {vuln.get('validated', False)}")
                else:
                    self.logger.warning(f"No vulnerabilities found for {url}")
                
                self.vulnerabilities.extend(results)
                self.scanned_urls.add(url)
            
            # Debug info about overall vulnerabilities before report generation
            self.logger.highlight(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
            self.logger.info(f"Output directory for report: {self.output_dir}")
            
            # Generate final report
            if self.vulnerabilities:
                report_path = self.reporter.generate_report(self.vulnerabilities)
                self.logger.info(f"Security testing completed. Report saved to {report_path}")
            else:
                self.logger.warning("No vulnerabilities found - creating empty report")
                report_path = self.reporter.generate_report([])
                self.logger.info(f"Empty report saved to {report_path}")
            
            return {
                "urls_discovered": len(self.discovered_urls),
                "urls_scanned": len(self.scanned_urls),
                "vulnerabilities_found": len(self.vulnerabilities),
                "report_path": report_path
            }
        
        finally:
            # Clean up resources
            self.scanner.stop()
    
    def _expand_scope(self) -> None:
        """Expand the scope by discovering additional URLs based on the scope setting."""
        self.logger.info(f"Expanding scope to {self.scope}")
        
        # Create and run discovery agent
        discovery_agent = create_agent_swarm(
            agent_type="discovery",
            llm_provider=self.llm_provider,
            scanner=self.scanner,
            config=self.config
        )
        
        new_urls = discovery_agent.discover_urls(
            base_url=self.url, 
            scope=self.scope,
            subdomains=self.scope == "subdomain"
        )
        
        self.discovered_urls.update(new_urls)
        self.logger.info(f"Discovered {len(new_urls)} additional URLs")
    
    def _process_url(self, url: str) -> List[Dict[str, Any]]:
        """Process a single URL with the agent swarm."""
        # Load the page
        page = self.scanner.load_page(url)
        if not page:
            self.logger.error(f"Failed to load page: {url}")
            return []
        
        # Extract page information
        page_info = self.scanner.extract_page_info(page)
        
        # Create specialized agent swarm
        agent_swarm = create_agent_swarm(
            agent_type="security",
            llm_provider=self.llm_provider,
            scanner=self.scanner,
            config=self.config
        )
        
        # Run the swarm and collect results
        vulnerabilities = agent_swarm.run(url, page, page_info)
        
        return vulnerabilities
