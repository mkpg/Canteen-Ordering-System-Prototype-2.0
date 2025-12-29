import os
from flask import Flask
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secure session management
app.secret_key = os.getenv('SECRET_KEY', 'your-fallback-secret-key')  # Replace fallback with a strong key

# MongoDB connection (ensure environment variable is properly set)
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set.")

# MongoDB client setup
client = MongoClient(MONGO_URI)
db = client.get_database()  # Defaults to the database specified in the URI