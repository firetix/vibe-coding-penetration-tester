import time
import uuid
import threading
import logging
from typing import Dict, List, Any, Optional

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.active_scans = {}
        self.completed_scans = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('web_ui')
    
    def create_session(self) -> str:
        session_id = str(uuid.uuid4())
        with self.lock:
            self.sessions[session_id] = {
                'created': time.time(),
                'last_activity': time.time()
            }
        return session_id
    
    def check_session(self, session_id: str) -> bool:
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            self.sessions[session_id]['last_activity'] = time.time()
            return True
    
    def start_scan(self, session_id: str, url: str, config: Dict[str, Any]) -> str:
        scan_id = str(uuid.uuid4())
        
        with self.lock:
            if session_id not in self.active_scans:
                self.active_scans[session_id] = {}
            
            self.active_scans[session_id][scan_id] = {
                'url': url,
                'config': config,
                'started': time.time(),
                'status': 'initializing',
                'progress': 0,
                'report_dir': None,
                'process': None,
                'vulnerabilities': []
            }
        
        return scan_id
    
    def get_active_scan(self, session_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if session_id not in self.active_scans:
                return None
            
            return self.active_scans[session_id].get(scan_id)
    
    def get_active_scans(self, session_id: str) -> List[Dict[str, Any]]:
        with self.lock:
            if session_id not in self.active_scans:
                return []
            
            # Return a copy of the active scans without the 'process' field
            scans = []
            for scan_id, scan in self.active_scans[session_id].items():
                scan_copy = scan.copy()
                if 'process' in scan_copy:
                    del scan_copy['process']
                scan_copy['id'] = scan_id
                scans.append(scan_copy)
            
            return scans
    
    def update_scan_status(self, session_id: str, scan_id: str, 
                          status: str, progress: int = None, 
                          report_dir: str = None,
                          vulnerabilities: List[Dict[str, Any]] = None) -> None:
        with self.lock:
            if session_id not in self.active_scans or scan_id not in self.active_scans[session_id]:
                return
            
            scan = self.active_scans[session_id][scan_id]
            
            if status:
                scan['status'] = status
            
            if progress is not None:
                scan['progress'] = progress
            
            if report_dir:
                scan['report_dir'] = report_dir
            
            if vulnerabilities:
                scan['vulnerabilities'] = vulnerabilities
            
            # If scan is completed, move it to completed_scans
            if status in ['completed', 'error', 'cancelled']:
                scan['completed'] = time.time()
                
                if session_id not in self.completed_scans:
                    self.completed_scans[session_id] = {}
                
                self.completed_scans[session_id][scan_id] = scan
                del self.active_scans[session_id][scan_id]
    
    def get_completed_scans(self, session_id: str) -> List[Dict[str, Any]]:
        with self.lock:
            if session_id not in self.completed_scans:
                return []
            
            scans = []
            for scan_id, scan in self.completed_scans[session_id].items():
                scan_copy = scan.copy()
                if 'process' in scan_copy:
                    del scan_copy['process']
                scan_copy['id'] = scan_id
                scans.append(scan_copy)
            
            return sorted(scans, key=lambda s: s.get('completed', 0), reverse=True)
    
    def cleanup_old_sessions(self, max_age_seconds: int = 3600) -> None:
        current_time = time.time()
        
        with self.lock:
            for session_id in list(self.sessions.keys()):
                session = self.sessions[session_id]
                
                if current_time - session['last_activity'] > max_age_seconds:
                    self.logger.info(f"Cleaning up inactive session: {session_id}")
                    
                    # Terminate any active scans
                    if session_id in self.active_scans:
                        for scan_id, scan in self.active_scans[session_id].items():
                            if scan.get('process') and hasattr(scan['process'], 'terminate'):
                                try:
                                    scan['process'].terminate()
                                except:
                                    pass
                    
                    # Remove session data
                    self.sessions.pop(session_id, None)
                    self.active_scans.pop(session_id, None)
                    self.completed_scans.pop(session_id, None)