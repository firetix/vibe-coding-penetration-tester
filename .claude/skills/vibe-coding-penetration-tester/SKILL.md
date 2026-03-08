# vibe-coding-penetration-tester Development Patterns

> Auto-generated skill from repository analysis

## Overview

This codebase is a Python-based penetration testing platform that combines web API functionality with LLM integration capabilities. The project follows a modular architecture with separate concerns for API routes, core LLM functionality, database persistence, and comprehensive testing across multiple levels. It emphasizes deployment flexibility and thorough documentation practices.

## Coding Conventions

### File Naming
- Use `snake_case` for all Python files
- Test files follow pattern: `test_*.py`
- E2E tests: `test_*_routes_e2e.py`

### Import Style
```python
# Use aliases for common imports
import pandas as pd
import numpy as np
from core import llm as llm_core
```

### Export Style
- Mixed approach using both `__all__` and direct imports
- Route files export endpoints directly
- Core modules use explicit exports

### Commit Messages
- Use conventional prefixes: `feat:`, `fix:`, `docs:`
- Keep messages concise (~48 characters average)
- Examples:
  - `feat: add new LLM model support`
  - `fix: resolve API route validation`
  - `docs: update deployment guide`

## Workflows

### API Route Development
**Trigger:** When someone wants to add a new API endpoint  
**Command:** `/new-api-endpoint`

1. Create route file in `web_api/routes/[route_name].py`
   ```python
   from flask import Blueprint, request, jsonify
   
   bp = Blueprint('route_name', __name__)
   
   @bp.route('/api/endpoint', methods=['POST'])
   def new_endpoint():
       # Implementation here
       return jsonify({"status": "success"})
   ```

2. Register endpoint in `web_api/__init__.py`
   ```python
   from web_api.routes import route_name
   app.register_blueprint(route_name.bp)
   ```

3. Write E2E tests in `tests/e2e/api/test_[route_name]_routes_e2e.py`
   ```python
   def test_new_endpoint_success(client):
       response = client.post('/api/endpoint', json={})
       assert response.status_code == 200
   ```

4. Update API documentation in `docs/api-contract.md`

### LLM Model Integration
**Trigger:** When someone wants to add a new LLM model or update model support  
**Command:** `/add-llm-model`

1. Update `core/llm.py` with model definitions
   ```python
   SUPPORTED_MODELS = {
       'new-model': {
           'provider': 'openai',
           'context_length': 4096,
           'capabilities': ['text', 'code']
       }
   }
   ```

2. Add model validation logic
   ```python
   def validate_model(model_name):
       if model_name not in SUPPORTED_MODELS:
           raise ValueError(f"Unsupported model: {model_name}")
   ```

3. Update README.md model catalog section
4. Add unit tests in `tests/unit/test_llm.py`
5. Update `main.py` and `templates/index.html` if UI changes needed

### Deployment Environment Setup
**Trigger:** When someone wants to deploy to a new platform or update deployment config  
**Command:** `/setup-deployment`

1. Update `.env.example` with new variables
   ```env
   # New deployment variables
   PLATFORM_API_KEY=your_key_here
   DEPLOYMENT_ENV=production
   ```

2. Create platform-specific config files (`Procfile`, `app.yaml`, etc.)
3. Update `requirements.txt` with any new dependencies
4. Add deployment documentation in `docs/deployment-[platform].md`
5. Update README.md deployment section

### Database Persistence Layer
**Trigger:** When someone wants to add database persistence or new data models  
**Command:** `/add-database-model`

1. Create migration files for different dialects in `web_api/store/migrations/`
   ```sql
   -- postgresql/001_create_table.sql
   CREATE TABLE IF NOT EXISTS new_table (
       id SERIAL PRIMARY KEY,
       created_at TIMESTAMP DEFAULT NOW()
   );
   ```

2. Add store classes in `web_api/store/[model_name]_store.py`
   ```python
   class ModelStore:
       def __init__(self, db_connection):
           self.db = db_connection
       
       def create(self, data):
           # Implementation
           pass
   ```

3. Update schema definitions in `web_api/store/schema.py`
4. Update database configuration in `web_api/store/db.py`
5. Write tests for database layer

### Test Suite Expansion
**Trigger:** When someone wants to add test coverage for new features  
**Command:** `/add-test-coverage`

1. Add unit tests in `tests/unit/test_[module].py`
   ```python
   import pytest
   from core.module import function_to_test
   
   def test_function_behavior():
       result = function_to_test(input_data)
       assert result == expected_output
   ```

2. Add integration tests in `tests/integration/test_[feature].py`
3. Add E2E tests in appropriate `tests/e2e/` subdirectories
4. Update `tests/conftest.py` with shared fixtures

### Documentation Update
**Trigger:** When someone wants to document features, architecture, or project planning  
**Command:** `/update-docs`

1. Create/update docs in `docs/` directory with descriptive filenames
2. Update README.md sections if core functionality changes
3. Add planning artifacts in `_bmad-output/` for architectural decisions
4. Update `project-context.md` with current project state

## Testing Patterns

### Test Organization
- **Unit tests**: `tests/unit/` - Test individual functions/classes
- **Integration tests**: `tests/integration/` - Test component interactions  
- **E2E tests**: `tests/e2e/` - Test complete workflows

### Test File Naming
```
tests/
├── unit/test_[module_name].py
├── integration/test_[feature_name].py
└── e2e/api/test_[route_name]_routes_e2e.py
```

### Test Structure
```python
def test_function_name_scenario():
    # Arrange
    input_data = setup_test_data()
    
    # Act
    result = function_under_test(input_data)
    
    # Assert
    assert result.status == 'success'
    assert len(result.data) > 0
```

## Commands

| Command | Purpose |
|---------|---------|
| `/new-api-endpoint` | Add new API route with tests and documentation |
| `/add-llm-model` | Integrate new LLM model with validation and catalog update |
| `/setup-deployment` | Configure deployment for new platform |
| `/add-database-model` | Create new data model with migrations and store |
| `/add-test-coverage` | Expand test suite across all levels |
| `/update-docs` | Create or update project documentation |