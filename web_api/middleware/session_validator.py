import logging
from functools import wraps
from flask import request, g

from web_api.helpers.request_parser import parse_request
from web_api.helpers.response_formatter import error_response

logger = logging.getLogger('web_api')

def validate_session(session_manager, auto_create=False, fallback_to_args=True, required=True):
    """Middleware for validating session ID."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = parse_request()
            session_id = data.get('session_id')
            
            # Try to get session ID from query parameters
            if not session_id and fallback_to_args:
                session_id = request.args.get('session_id')
            
            # Handle case when session ID is not provided
            if not session_id:
                if required:
                    return error_response("Session ID is required", 400)
                else:
                    # If session ID is not required, create a new one
                    session_id = session_manager.create_session()
                    g.session_id = session_id
                    logger.info(f"Created new session: {session_id} (no session ID provided)")
                    return f(*args, **kwargs)
                
            # Check if session is valid
            valid = session_manager.check_session(session_id)
            
            # Handle invalid session
            if not valid:
                if auto_create:
                    # Create a new session if auto_create is True
                    old_session_id = session_id
                    session_id = session_manager.create_session()
                    g.session_id = session_id
                    logger.info(f"Created new session: {session_id} (replacing invalid session: {old_session_id})")
                    return f(*args, **kwargs)
                else:
                    return error_response("Invalid session", 401)
            
            # Store the valid session ID in Flask's g object
            g.session_id = session_id
            return f(*args, **kwargs)
        return decorated_function
    return decorator