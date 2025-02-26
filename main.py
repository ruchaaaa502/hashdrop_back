import sys
import os
from app import create_app

# Ensure the correct module path is set
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Create the Flask app
app = create_app()

if __name__ == '__main__':
    # Run Flask only for local development
    app.run(debug=True, host='0.0.0.0', port=5000)

