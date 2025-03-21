import json
import logging
from flask import request

logger = logging.getLogger('web_api')

def parse_request():
    """Parse request data from any content type."""
    data = {}
    
    if request.content_type and 'application/json' in request.content_type:
        if request.is_json:
            data = request.json
        else:
            logger.warning("Request has JSON content type but no valid JSON data")
    elif request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
        data = request.form
    elif request.content_type and 'multipart/form-data' in request.content_type:
        data = request.form
    else:
        data = request.form or {}
    
    # Add query parameters for form or URL params
    for key, value in request.args.items():
        if key not in data:
            data[key] = value
            
    return data

def get_json_param(data, key, default=None, required=False):
    """Extract and handle JSON-encoded param value."""
    value = data.get(key, default)
    
    if value is None and required:
        return None
        
    if isinstance(value, dict):
        return value
        
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
            
    return value

def validate_required_fields(data, required_fields):
    """Validate that all required fields are present."""
    missing = [field for field in required_fields if not data.get(field)]
    
    if missing:
        return False, missing
        
    return True, []

def normalize_url(url):
    """Ensure URL has a proper scheme."""
    if url and not url.startswith(('http://', 'https://')):
        return f"http://{url}"
    return url