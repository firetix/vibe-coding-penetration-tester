import os
import time
import uuid
import json
import threading
import logging
from typing import Dict, List, Any, Optional

class SessionManager:
    def __init__(self, session_file: str = 'sessions.json'):
        self.sessions = {}
        self.active_scans = {}
        self.completed_scans = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('web_ui')
        self.session_file = session_file
        
        # Attempt to load sessions from file if it exists
        self._load_sessions()
    
    def _load_sessions(self):
        """Load sessions from the session file if it exists"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r') as f:
                    stored_data = json.load(f)
                    
                    # Load sessions with basic info
                    for session_id, session_data in stored_data.items():
                        if session_id not in self.sessions:
                            self.sessions[session_id] = {
                                'created': session_data.get('created', time.time()),
                                'last_activity': time.time()  # Reset last activity to now
                            }
                
                self.logger.info(f"Loaded {len(self.sessions)} sessions from {self.session_file}")
        except Exception as e:
            self.logger.error(f"Error loading sessions from file: {str(e)}")
    
    def _save_sessions(self):
        """Save current sessions to the session file"""
        try:
            with open(self.session_file, 'w') as f:
                # Create a simplified version of the sessions for storage
                stored_data = {}
                for session_id, session_data in self.sessions.items():
                    stored_data[session_id] = {
                        'created': session_data.get('created', time.time()),
                        'last_activity': session_data.get('last_activity', time.time())
                    }
                
                json.dump(stored_data, f)
            self.logger.debug(f"Saved {len(self.sessions)} sessions to {self.session_file}")
        except Exception as e:
            self.logger.error(f"Error saving sessions to file: {str(e)}")
    
    def create_session(self) -> str:
        session_id = str(uuid.uuid4())
        with self.lock:
            self.sessions[session_id] = {
                'created': time.time(),
                'last_activity': time.time()
            }
            # Save sessions to maintain persistence
            self._save_sessions()
            
        self.logger.debug(f"Created new session: {session_id}, total sessions: {len(self.sessions)}")
        return session_id
    
    def check_session(self, session_id: str) -> bool:
        with self.lock:
            if session_id not in self.sessions:
                self.logger.debug(f"Session check failed for {session_id}, not found in {list(self.sessions.keys())}")
                return False
            
            self.sessions[session_id]['last_activity'] = time.time()
            # No need to save on every check - too many writes
            self.logger.debug(f"Session check passed for {session_id}, last activity updated")
            return True
            
    def get_all_sessions(self) -> List[str]:
        """Return a list of all active session IDs for debugging"""
        with self.lock:
            return list(self.sessions.keys())
    
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
                          vulnerabilities: List[Dict[str, Any]] = None,
                          action_plan: List[str] = None,
                          current_task: str = None) -> None:
        with self.lock:
            if session_id not in self.active_scans or scan_id not in self.active_scans[session_id]:
                self.logger.warning(f"Tried to update non-existent scan: {session_id}/{scan_id}")
                return
            
            scan = self.active_scans[session_id][scan_id]
            
            if status:
                self.logger.info(f"Updating scan {scan_id} status: {scan.get('status', 'none')} -> {status}")
                scan['status'] = status
            
            if progress is not None:
                scan['progress'] = progress
            
            if report_dir:
                self.logger.info(f"Setting report_dir for scan {scan_id}: {report_dir}")
                scan['report_dir'] = report_dir
            
            if vulnerabilities:
                scan['vulnerabilities'] = vulnerabilities
                
            # Store action plan if provided
            if action_plan:
                old_count = len(scan.get('action_plan', []))
                
                if 'action_plan' not in scan:
                    scan['action_plan'] = []
                
                # Completely replace the action plan if we're finalizing
                if status == 'completed':
                    self.logger.info(f"Replacing action plan with {len(action_plan)} items for completed scan")
                    scan['action_plan'] = action_plan
                else:
                    # Add new items to existing action plan
                    for item in action_plan:
                        if item not in scan['action_plan']:
                            scan['action_plan'].append(item)
                
                new_count = len(scan.get('action_plan', []))
                self.logger.info(f"Action plan updated: {old_count} -> {new_count} items")
                        
            # Update current task if provided
            if current_task:
                self.logger.info(f"Setting current task: {current_task}")
                scan['current_task'] = current_task
            
            # Make sure scan data is saved
            self._save_sessions()
            
            # If scan is completed, move it to completed_scans
            if status in ['completed', 'error', 'cancelled']:
                self.logger.info(f"Moving scan {scan_id} to completed scans with status {status}")
                scan['completed'] = time.time()
                
                # Make a deep copy of the scan to move to completed_scans
                import copy
                scan_copy = copy.deepcopy(scan)
                
                # Check that required fields are set
                if status == 'completed' and not scan_copy.get('report_dir'):
                    self.logger.warning(f"Completed scan {scan_id} has no report_dir set!")
                
                if session_id not in self.completed_scans:
                    self.completed_scans[session_id] = {}
                
                self.logger.info(f"Copying scan with report_dir: {scan_copy.get('report_dir')}")
                self.completed_scans[session_id][scan_id] = scan_copy
                
                # Remove the scan from active_scans
                del self.active_scans[session_id][scan_id]
                
                # Make sure scan data is saved after moving to completed
                self._save_sessions()
                
                # Double-check that the completed scan has the right data
                if session_id in self.completed_scans and scan_id in self.completed_scans[session_id]:
                    completed = self.completed_scans[session_id][scan_id]
                    self.logger.info(f"Verified completed scan: status={completed.get('status')}, report_dir={completed.get('report_dir')}")
    
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