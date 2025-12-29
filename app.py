from flask import Flask
from pymongo import MongoClient
import os

# Initialize Flask application
app = Flask(__name__)

# Configuration for MongoDB (using MongoDB Atlas)
mongo_uri = os.getenv("MONGO_URI", "")
if not mongo_uri:
    raise ValueError("The MONGO_URI environment variable is not set.")
client = MongoClient(mongo_uri)
db = client.get_database()

# Set the SECRET_KEY for session management and security
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "change_this_to_a_random_secret_key")

# Define a basic route
@app.route('/')
def home():
    return "Hello, World! The app is connected to MongoDB Atlas."

# Run the app on specified PORT (fallback to 5000)
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)