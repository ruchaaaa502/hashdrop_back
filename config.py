import os
from dotenv import load_dotenv
from flask_mail import Mail

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://user1:shalakapoojari@hashdrop.1qnye.mongodb.net/db')
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'hashdropco@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'nlpc ixix vdem cqdi')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'hashdropco@gmail.com')
    UPLOAD_FOLDER = './encrypted_files'
    HCAPTCHA_SITE_KEY = 'a04e9902-ee6a-4716-a550-ed944a76314e'  # Replace with your site key
    HCAPTCHA_SECRET_KEY= 'ES_6992a325e3ea4ead98228b6d2c2eb5ff'  # Replace with your secret key


# Instantiate Mail but DO NOT initialize with app here
mail = Mail()