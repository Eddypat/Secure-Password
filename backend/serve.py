"""
serve.py
Production entry point for Cipherkeep.

Runs the exact same Flask app (app.py) but through Waitress, a proper
production-grade WSGI server, instead of Flask's built-in development
server. Use this for any real deployment (Render, Railway, PythonAnywhere,
a VPS, etc.) instead of `python app.py`.

Locally, you can still test this the same way:
    python serve.py
It will read the PORT environment variable if the host platform sets one
(most platforms, including Render, do this automatically), otherwise it
defaults to 5000.
"""

import os
from waitress import serve
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Serving Cipherkeep on http://0.0.0.0:{port}  (production mode via waitress)")
    serve(app, host="0.0.0.0", port=port)
