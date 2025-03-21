#!/usr/bin/env python3

import os
from web_api import create_app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    # Run the application
    port = int(os.environ.get('PORT', 5050))
    app.run(debug=True, host='0.0.0.0', port=port)