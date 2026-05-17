from app import app

# Vercel uses the exported `app` object for Python WSGI deployments.
# The Flask app already defines routes for `/`, `/analyze`, and `/api/analyze`.

if __name__ == "__main__":
    app.run()
