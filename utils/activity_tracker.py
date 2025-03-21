import time
import re
import logging
from typing import Dict, List, Any, Optional

class ActivityTracker:
    def __init__(self):
        self.activities: Dict[str, List[Dict[str, Any]]] = {}
    
    def add_activity(self, session_id: str, activity_type: str, description: str, 
                    details: Optional[Dict[str, Any]] = None, agent_name: Optional[str] = None) -> Dict[str, Any]:
        if session_id not in self.activities:
            self.activities[session_id] = []
        
        description = self._clean_description(description)
        
        if self._is_duplicate_activity(session_id, activity_type, description, agent_name):
            existing = self._find_duplicate(session_id, activity_type, description, agent_name)
            return existing if existing else {}
        
        activity = self._create_activity(activity_type, description, details, agent_name)
        self.activities[session_id].append(activity)
        
        self._prune_activities(session_id)
        self._log_activity(description, activity_type, agent_name)
        
        return activity
    
    def get_activities(self, session_id: str) -> List[Dict[str, Any]]:
        return self.activities.get(session_id, [])
    
    def clear_activities(self, session_id: str) -> None:
        if session_id in self.activities:
            self.activities[session_id] = []
    
    def parse_agent_message(self, session_id: str, message: str, agent_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not isinstance(message, str) or not message.strip():
            return None
        
        message = self._clean_message(message)
        
        for pattern, activity_type, activity_name in self._get_activity_patterns():
            if re.search(pattern, message, re.IGNORECASE):
                return self.add_activity(session_id, activity_type, 
                                       f"{activity_name}: {message[:100]}", 
                                       agent_name=agent_name)
        
        # If no specific pattern matches but has agent activity
        if "agent" in message.lower() or "testing" in message.lower():
            return self.add_activity(session_id, "general", 
                                   f"Activity: {message[:100]}", 
                                   agent_name=agent_name)
        
        return None
    
    def _clean_description(self, description: str) -> str:
        description = description.strip()
        description = re.sub(r'\s*Activity\s*$', '', description)
        description = re.sub(r'\'}]\}.*?$', '', description)
        description = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', description)
        return description
    
    def _is_duplicate_activity(self, session_id: str, activity_type: str, 
                              description: str, agent_name: Optional[str]) -> bool:
        return self._find_duplicate(session_id, activity_type, description, agent_name) is not None
    
    def _find_duplicate(self, session_id: str, activity_type: str, 
                      description: str, agent_name: Optional[str]) -> Optional[Dict[str, Any]]:
        recent_timeframe = 5.0  # seconds
        current_time = time.time()
        description_fingerprint = description[-100:] if len(description) > 100 else description
        
        for existing in reversed(self.activities[session_id][-10:]):
            if current_time - existing.get('timestamp', 0) > recent_timeframe:
                continue
            
            if existing.get('type') != activity_type:
                continue
            
            existing_desc = existing.get('description', '')
            existing_fingerprint = existing_desc[-100:] if len(existing_desc) > 100 else existing_desc
            
            if existing_fingerprint == description_fingerprint and existing.get('agent') == agent_name:
                return existing
        
        return None
    
    def _create_activity(self, activity_type: str, description: str, 
                       details: Optional[Dict[str, Any]], agent_name: Optional[str]) -> Dict[str, Any]:
        activity = {
            'timestamp': time.time(),
            'time': time.strftime('%H:%M:%S'),
            'type': activity_type,
            'description': description,
            'agent': agent_name
        }
        
        if details:
            activity['details'] = details
        
        return activity
    
    def _prune_activities(self, session_id: str) -> None:
        if len(self.activities[session_id]) > 200:
            self.activities[session_id] = self.activities[session_id][-200:]
    
    def _log_activity(self, description: str, activity_type: str, agent_name: Optional[str]) -> None:
        if "Agent Activity:" not in description:
            agent_suffix = f" (Agent: {agent_name})" if agent_name else ""
            logging.info(f"Agent Activity: [{activity_type}] {description}{agent_suffix}")
    
    def _clean_message(self, message: str) -> str:
        message = message.strip()
        message = re.sub(r'\s*Activity\s*$', '', message)
        message = re.sub(r'\'}]\}.*?$', '', message)
        
        duplicate_pattern = r'(INFO - Agent Activity: \[\w+\]\s*)+'
        if re.match(duplicate_pattern, message):
            clean_parts = re.split(r'INFO - Agent Activity: \[\w+\]\s*', message)
            actual_message = next((part for part in reversed(clean_parts) if part.strip()), "")
            
            if actual_message:
                message = self._extract_agent_name(actual_message)
        
        return message
    
    def _extract_agent_name(self, message: str) -> str:
        agent_pattern = r'\(Agent:\s*([^)]+)\)'
        agent_matches = re.findall(agent_pattern, message)
        
        if agent_matches:
            message = re.sub(r'\s*\(Agent:\s*[^)]+\)', '', message).strip()
        
        return message
    
    def _get_activity_patterns(self) -> List[tuple]:
        return [
            # XSS tests
            (r'testing.*XSS|cross-site scripting|Injecting.*script|DOM-based XSS', 'xss_test', 'XSS Testing'),
            (r'testing.*SQL injection|SQLi test|database injection|SQL vulnerability', 'sqli_test', 'SQL Injection Testing'),
            (r'testing.*CSRF|cross-site request forgery', 'csrf_test', 'CSRF Testing'),
            
            # Discovery patterns
            (r'crawling|mapping|enumerating|discovering endpoints', 'discovery', 'Discovery'),
            (r'analyzing.*form|identifying input fields', 'form_analysis', 'Form Analysis'),
            
            # Authentication tests
            (r'testing auth|password|credential|login|session|cookie', 'auth_test', 'Authentication Testing'),
            
            # Security headers and configuration
            (r'checking.*headers|security headers|content security policy|CSP', 'header_check', 'Security Header Check'),
            
            # General security tests
            (r'injection test|command injection|OS command|path traversal', 'injection_test', 'Injection Testing'),
            (r'scanning|vulnerability scan|security scan', 'scanning', 'Security Scanning'),
            
            # Report generation
            (r'generating.*report|summarizing|creating summary', 'reporting', 'Report Generation'),
            
            # Vulnerability found
            (r'found.*vulnerability|detected.*issue|security issue identified', 'vulnerability', 'Vulnerability Found'),
            
            # Planning
            (r'planning|creating plan|prioritizing|strategy', 'planning', 'Planning'),
            
            # Analysis
            (r'analyzing|evaluating|assessing|investigating', 'analysis', 'Analysis'),
        ]