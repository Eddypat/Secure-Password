# Cipherkeep — Secure Password-Based Encryption & Decryption System

## Run locally (development)
```bash
cd backend
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Run in production (any host: Render, Railway, PythonAnywhere, a VPS)
```bash
cd backend
pip install -r requirements.txt
python serve.py
```
This uses `waitress`, a real production WSGI server, instead of Flask's dev server.
It reads the `PORT` environment variable automatically (most hosts set this for you),
defaulting to 5000 if none is set.

## Deploying to Render
1. Push this project to a GitHub repo.
2. On Render.com: New → Blueprint → connect the repo. Render will read `render.yaml`
   automatically and configure everything (build command, start command, Python version).
   Alternatively, create a Web Service manually with:
   - Root directory: `backend`
   - Build command: `pip install -r requirements.txt`
   - Start command: `python serve.py`
3. Render provisions a public HTTPS URL automatically — no extra TLS setup needed.

## Files
```
backend/
  app.py             Flask REST API (routes: /api/encrypt, /api/decrypt,
                      /api/strength, /api/encrypt-file, /api/decrypt-file)
  crypto_engine.py    All cryptography: key derivation, AES-GCM encrypt/decrypt,
                      password strength scoring
  serve.py            Production entry point (waitress WSGI server)
  requirements.txt    Pinned dependencies for reproducible installs
  Procfile            Start command for Heroku-style platforms
frontend/
  index.html          UI markup
  style.css            Dark "vault/cipher" themed styling
  script.js            Client logic — calls the Flask API, no crypto happens here
render.yaml            One-click deployment blueprint for Render.com
```
