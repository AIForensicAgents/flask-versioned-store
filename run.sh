#!/bin/bash
# Generate self-signed certificate if not present
if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
    echo "Generating self-signed certificate..."
    python generate_cert.py
fi

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
