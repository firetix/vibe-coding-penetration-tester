import logging
import re
import time
import os
import sys
from typing import List, Dict, Any, Set, Optional

class LoggingManager:
    def __init__(self):
        self.setup_logging()
        self.ui_log_handler = UILogHandler() if not self.is_vercel else None
        if self.ui_log_handler:
            self.logger.addHandler(self.ui_log_handler)
    
    @property
    def is_vercel(self) -> bool:
        return os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None
    
    def setup_logging(self):
        handlers = [logging.StreamHandler()]
        if not self.is_vercel:
            try:
                handlers.append(logging.FileHandler('web_ui.log'))
            except OSError as e:
                print(f"Warning: Could not create log file: {str(e)}", file=sys.stderr)
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )
        self.logger = logging.getLogger('web_ui')
        
        if self.is_vercel:
            self.logger.info("Running in Vercel environment, file logging disabled")
    
    def get_logger(self):
        return self.logger
    
    def get_ui_logs(self):
        return self.ui_log_handler.get_logs() if self.ui_log_handler else []
    
    def clear_ui_logs(self):
        if self.ui_log_handler:
            self.ui_log_handler.clear()


class UILogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.logs = []
        self.recent_messages: Set[str] = set()
        self.max_recent = 50
    
    def emit(self, record):
        try:
            if record.levelno < logging.INFO:
                return
                
            msg = self._format_message(record)
            
            if self._is_duplicate_message(msg):
                return
                
            self.logs.append({
                'time': time.strftime('%H:%M:%S'),
                'level': record.levelname,
                'message': msg
            })
            
            if len(self.logs) > 100:
                self.logs = self.logs[-100:]
        except Exception:
            self.handleError(record)
    
    def _format_message(self, record) -> str:
        msg = self.format(record)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        msg = ansi_escape.sub('', msg)
        
        if "Agent Activity:" in msg:
            msg = re.sub(r'\s*Activity\s*$', '', msg)
            msg = re.sub(r'\'}]\}.*?$', '', msg)
            msg = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', msg)
            
            if msg.count("INFO - Agent Activity:") > 1:
                clean_parts = re.split(r'INFO - Agent Activity: \[\w+\]\s*', msg)
                actual_message = next((part for part in reversed(clean_parts) if part.strip()), "")
                
                if actual_message.strip():
                    actual_message = self._clean_message(actual_message)
                    msg = f"INFO - Agent Activity: {actual_message.strip()}"
        
        return msg
    
    def _clean_message(self, message: str) -> str:
        message = re.sub(r'\s*Activity\s*$', '', message)
        message = re.sub(r'\'}]\}.*?$', '', message)
        message = re.sub(r'(\(Agent:\s*[^)]+\))\s*(\(Agent:.*?\))+', r'\1', message)
        return message
    
    def _is_duplicate_message(self, msg: str) -> bool:
        if "Agent Activity:" not in msg:
            return False
            
        message_checksum = msg.strip()[-50:]
        if message_checksum in self.recent_messages:
            return True
        
        self.recent_messages.add(message_checksum)
        if len(self.recent_messages) > self.max_recent:
            self.recent_messages.clear()
        
        return False
    
    def get_logs(self) -> List[Dict[str, Any]]:
        return self.logs
    
    def clear(self):
        self.logs = []
        self.recent_messages.clear()