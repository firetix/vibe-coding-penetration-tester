"""WSGI entry point for the Vibe web API."""

from web_api import create_app

# Create the application for WSGI servers to use
app = create_app()
