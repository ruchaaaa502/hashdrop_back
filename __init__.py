import os
import logging
from flask import Flask
from flask_pymongo import PyMongo
from flask_mail import Mail
from app.config import Config

# Initialize extensions
mongo = PyMongo()
mail = Mail()

def create_app():
    """Factory function to create and configure the Flask application."""
    app = Flask(__name__)

    # Load configurations
    app.config.from_object(Config)

    # Initialize extensions
    mongo.init_app(app)
    mail.init_app(app)

    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Import and register blueprints dynamically
    blueprint_modules = [
        ("app.routes.auth", "auth_bp", "/auth"),
        ("app.routes.admin", "admin_bp", "/admin"),
        ("app.routes.user", "user_bp", "/user"),
        ("app.routes.main", "main_bp", "/"),
        ("app.routes.file_management", "file_management_bp", "/files"),
    ]

    for module, bp_name, url_prefix in blueprint_modules:
        try:
            blueprint = __import__(module, fromlist=[bp_name])
            app.register_blueprint(getattr(blueprint, bp_name), url_prefix=url_prefix)
            logger.info(f"Registered blueprint: {bp_name} at {url_prefix}")
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to register blueprint {bp_name}: {e}")

    return app
