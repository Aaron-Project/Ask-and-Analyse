# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import pandas as pd
# import google.generativeai as genai
# import os
# import bcrypt
# import sqlite3
# import jwt
# from datetime import datetime, timedelta
# from dotenv import load_dotenv
# import logging

# # Load environment variables
# load_dotenv()

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Validate required environment variables
# GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
# NEWS_API_KEY = os.getenv("NEWS_API_KEY")
# JWT_SECRET = os.getenv("JWT_SECRET")

# if not all([GOOGLE_API_KEY, NEWS_API_KEY, JWT_SECRET]):
#     raise ValueError("Missing required environment variables. Check your .env file.")

# # Configure Google Gemini API
# genai.configure(api_key=GOOGLE_API_KEY)
# model = genai.GenerativeModel("gemini-1.5-pro-latest")

# # Initialize Flask app
# app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "*"}})

# # SQLite Database
# DB_FILE = "users.db"

# def init_db():
#     """Initialize the SQLite database."""
#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS users (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             name TEXT NOT NULL,
#             email TEXT UNIQUE NOT NULL,
#             password TEXT NOT NULL,
#             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#         )
#     """)
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS history (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             email TEXT NOT NULL,  
#             username TEXT NOT NULL,
#             query_searched TEXT NOT NULL,
#             query_done_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#             response_status TEXT NOT NULL,
#             filename TEXT NOT NULL
#         )
#     """)
#     conn.commit()
#     conn.close()

# init_db()

# # Helper Functions
# def validate_email(email):
#     """Basic email validation."""
#     return "@" in email and "." in email

# def log_history(email, username, query, response_status, filename):
#     """Log query history to the database."""
#     try:
#         conn = sqlite3.connect(DB_FILE)
#         cursor = conn.cursor()
#         cursor.execute("""
#             INSERT INTO history (email, username, query_searched, response_status, filename)
#             VALUES (?, ?, ?, ?, ?)
#         """, (email, username, query, response_status, filename))
#         conn.commit()
#         conn.close()
#     except Exception as e:
#         logger.error(f"Failed to log history: {e}")

# # Middleware: Verify JWT Token
# def verify_token(f):
#     """Middleware to verify JWT token."""
#     def decorated_function(*args, **kwargs):
#         token = request.headers.get("Authorization")

#         if not token:
#             return jsonify({"error": "Token is missing"}), 401

#         try:
#             # Decode the token
#             decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
#             request.user = decoded_token  # Attach user data to the request object
#         except jwt.ExpiredSignatureError:
#             return jsonify({"error": "Token has expired"}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({"error": "Invalid token"}), 401

#         return f(*args, **kwargs)

#     # Preserve the original function name
#     decorated_function.__name__ = f.__name__
#     return decorated_function

# # Routes
# @app.route("/register", methods=["POST"])
# def register():
#     """Register a new user."""
#     data = request.json
#     name, email, password = data.get("name"), data.get("email"), data.get("password")

#     if not all([name, email, password]):
#         return jsonify({"error": "All fields are required"}), 400

#     if not validate_email(email):
#         return jsonify({"error": "Invalid email format"}), 400

#     hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

#     try:
#         conn = sqlite3.connect(DB_FILE)
#         cursor = conn.cursor()
#         cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
#                        (name, email, hashed_password))
#         conn.commit()
#         conn.close()
#         return jsonify({"message": "User registered successfully!"}), 201
#     except sqlite3.IntegrityError:
#         return jsonify({"error": "Email already exists"}), 400
#     except Exception as e:
#         logger.error(f"Registration error: {e}")
#         return jsonify({"error": "An error occurred during registration"}), 500

# @app.route("/login", methods=["POST"])
# def login():
#     """Authenticate a user."""
#     data = request.json
#     email, password = data.get("email"), data.get("password")

#     if not email or not password:
#         return jsonify({"error": "Email and password are required"}), 400

#     try:
#         conn = sqlite3.connect(DB_FILE)
#         cursor = conn.cursor()
#         cursor.execute("SELECT id, name, password FROM users WHERE email = ?", (email,))
#         user = cursor.fetchone()
#         conn.close()

#         if user and bcrypt.checkpw(password.encode(), user[2].encode()):
#             # Generate JWT token with email in the payload
#             token = jwt.encode(
#                 {"id": user[0], "name": user[1], "email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
#                 JWT_SECRET,
#                 algorithm="HS256"
#             )

#             return jsonify({
#                 "message": "Login successful!",
#                 "token": token,
#                 "user": {
#                     "id": user[0],
#                     "name": user[1],
#                     "email": email
#                 }
#             }), 200
#         else:
#             return jsonify({"error": "Invalid email or password"}), 401

#     except sqlite3.Error as e:
#         logger.error(f"Database error during login: {e}")
#         return jsonify({"error": "An error occurred during login"}), 500

#     except Exception as e:
#         logger.error(f"Unexpected error during login: {e}")
#         return jsonify({"error": "An unexpected error occurred"}), 500

# @app.route("/query_csv", methods=["POST"])
# @verify_token  # Apply the middleware
# def query_csv():
#     """Query a CSV file using Gemini."""
#     try:
#         if "file" not in request.files or "query" not in request.form:
#             return jsonify({"error": "File and query are required"}), 400
        
#         file, query = request.files["file"], request.form["query"]

#         if file.filename == "":
#             return jsonify({"error": "No file uploaded"}), 400

#         if not file.filename.endswith('.csv'):
#             return jsonify({"error": "File must be a CSV"}), 400

#         df = pd.read_csv(file)
#         data_dict = df.to_dict(orient="records")

#         response = model.generate_content(f"Answer this query using the dataset:\n{data_dict}\n\nQuery: {query}")
#         response_text = response.text.strip().replace("*", "")

#         # Log history
#         username = request.user.get("name", "anonymous")
#         email = request.user.get("email")  # Get email from the token
#         log_history(email, username, query, "success", file.filename)

#         return jsonify({"query": query, "response": response_text})
#     except pd.errors.EmptyDataError:
#         return jsonify({"error": "The uploaded CSV file is empty"}), 400
#     except pd.errors.ParserError:
#         return jsonify({"error": "The uploaded file is not a valid CSV"}), 400
#     except Exception as e:
#         logger.error(f"Query CSV error: {e}")
#         return jsonify({"error": str(e)}), 500


# @app.route("/get-history", methods=["GET"])
# @verify_token  # Apply the middleware
# def get_history():
#     """Fetch query history for a user."""
#     try:
#         # Extract email from the request object (attached by the middleware)
#         email = request.user.get("email")

#         if not email:
#             logger.error("Email not found in token")
#             return jsonify({"error": "Email not found in token"}), 400

#         # Connect to the database
#         conn = sqlite3.connect(DB_FILE)
#         cursor = conn.cursor()

#         # Fetch history for the logged-in user using their email
#         cursor.execute("""
#             SELECT query_searched, response_status, filename, query_done_time
#             FROM history
#             WHERE email = ?
#             ORDER BY query_done_time DESC
#         """, (email,))

#         history_data = cursor.fetchall()
#         conn.close()

#         if not history_data:
#             logger.info(f"No history found for email: {email}")
#             return jsonify({"message": "No history found.", "history": []}), 200

#         # Format the history data
#         history = [{
#             "query_searched": row[0],
#             "response_status": row[1],
#             "filename": row[2],
#             "query_done_time": row[3]
#         } for row in history_data]

#         return jsonify({"history": history}), 200

#     except sqlite3.Error as e:
#         logger.error(f"Database error while fetching history: {e}")
#         return jsonify({"error": "An error occurred while fetching history"}), 500

#     except Exception as e:
#         logger.error(f"Unexpected error while fetching history: {e}")
#         return jsonify({"error": "An unexpected error occurred"}), 500

# if __name__ == "__main__":
#     app.run(debug=True)
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import google.generativeai as genai
import os
import bcrypt
import sqlite3
import requests
from dotenv import load_dotenv

# Load API Keys
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
NEWS_API_KEY = os.getenv("NEWS_API_KEY")

# Configure Google Gemini API
if not GOOGLE_API_KEY:
    raise ValueError("Google API Key not found. Check your .env file.")

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("gemini-1.5-pro-latest")

# Initialize Flask App
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# SQLite Database
DB_FILE = "users.db"

def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            query_searched TEXT NOT NULL,
            query_done_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            response_status TEXT NOT NULL,
            filename TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ✅ User Registration
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    name, email, password = data.get("name"), data.get("email"), data.get("password")

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                       (name, email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ✅ User Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email, password = data.get("email"), data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            return jsonify({
                "message": "Login successful!",
                "user": {
                    "id": user[0],
                    "name": user[1],
                    "email": email
                }
            }), 200
        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ✅ Query CSV with History Logging
@app.route("/query_csv", methods=["POST"])
def query_csv():
    try:
        # Check if file and query are present
        if "file" not in request.files or "query" not in request.form:
            return jsonify({"error": "File and query are required"}), 400
        
        file, query = request.files["file"], request.form["query"]

        # Check if a file was uploaded
        if file.filename == "":
            return jsonify({"error": "No file uploaded"}), 400

        # Read and process the CSV file
        df = pd.read_csv(file)
        data_dict = df.to_dict(orient="records")

        # Generate a response using the Gemini model
        response = model.generate_content(f"Answer this query using the dataset:\n{data_dict}\n\nQuery: {query}")
        response_text = response.text.strip().replace("*", "")

        # Log the query history (optional, without email)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO history (username, query_searched, response_status, filename)
            VALUES (?, ?, ?, ?)
        """, ("Anonymous", query, "success", file.filename))  # Use "Anonymous" as the username
        conn.commit()
        conn.close()

        # Return the response
        return jsonify({"query": query, "response": response_text})
    except pd.errors.EmptyDataError:
        return jsonify({"error": "The uploaded CSV file is empty"}), 400
    except pd.errors.ParserError:
        return jsonify({"error": "The uploaded file is not a valid CSV"}), 400
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ✅ Fetch History
@app.route("/history", methods=["GET"])
def get_history():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        username = user[0] if user else "Unknown"
        
        cursor.execute("""
            SELECT query_searched, query_done_time, response_status, filename
            FROM history
            WHERE username = ?
        """, (username,))
        history_data = cursor.fetchall()
        conn.close()

        history = [{
            "query_searched": row[0],
            "query_done_time": row[1],
            "response_status": row[2],
            "filename": row[3]
        } for row in history_data]

        return jsonify({"history": history}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ✅ Fetch News from API
NEWS_API_URL = "https://newsapi.org/v2/top-headlines"
@app.route("/news", methods=["GET"])
def get_news():
    search_query = request.args.get("query", "")
    
    params = {
        "apiKey": NEWS_API_KEY,
        "sources": "the-hindu",
        "q": search_query if search_query else None
    }
    params = {k: v for k, v in params.items() if v is not None}
    
    try:
        response = requests.get(NEWS_API_URL, params=params)
        news_data = response.json()

        if response.status_code == 200 and news_data.get("articles"):
            return jsonify({"news": news_data["articles"]}), 200
        return jsonify({"news": [], "message": "No articles found from The Hindu"}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)