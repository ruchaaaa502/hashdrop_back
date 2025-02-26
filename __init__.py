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

    # Import and register blueprints
    try:
        from app.routes.auth import bp as auth_bp
        from app.routes.admin import bp as admin_bp
        from app.routes.user import bp as user_bp
        from app.routes.main import bp as main_bp
        from app.routes.file_management import bp as file_management_bp

        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(admin_bp, url_prefix='/admin')
        app.register_blueprint(user_bp, url_prefix='/user')
        app.register_blueprint(main_bp, url_prefix='/')
        app.register_blueprint(file_management_bp, url_prefix='/files')

    except ImportError as e:
        print(f"Error importing blueprints: {e}")

    return app
