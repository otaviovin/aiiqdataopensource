# Importing necessary modules from Flask and other libraries

# === Flask core and utilities ===
# Flask is a lightweight WSGI web application framework for building web servers and APIs.
from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, session, send_file, Response
)

# === MongoDB and BSON ===
# GridFS is a specification for storing large files in MongoDB.
import gridfs

# MongoClient is used to connect and interact with a MongoDB database.
from pymongo import MongoClient

# BSON (Binary JSON) is used for handling special MongoDB types like ObjectId.
from bson import ObjectId
import bson  # May be redundant unless explicitly used elsewhere.

# === Chatbot Integration ===
# Function for AI-based question answering using a custom chatbot module.
from chatbot import ask_question
from chatdata import ask_question_data

# === Environment and System Utilities ===
# OS is used for interacting with the operating system (e.g., paths, env vars).
import os

# dotenv loads environment variables from a .env file.
from dotenv import load_dotenv

# re is used for regular expressions and string pattern matching.
import re

# webbrowser is used to open URLs in the user's default browser.
import webbrowser

# datetime and timedelta are used for date and time operations.
import datetime
from datetime import timedelta

# tempfile is used to create temporary files and directories.
import tempfile

# traceback is useful for printing exception stack traces.
import traceback

# secrets generates cryptographically secure random values.
import secrets

# === Email Support ===
# Email MIME classes for composing multipart email content (plain text, HTML, etc.).
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# smtplib is used for sending emails via SMTP.
import smtplib

# SendGrid is a third-party email delivery service.
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# === Data Processing and Analysis ===
# pandas is used for working with structured/tabular data like CSVs.
import pandas as pd

# stripe is used for integrating Stripe payment APIs (e.g., checkout, billing).
import stripe

# requests is used to send HTTP requests and interact with APIs.
import requests

# === Plotting and Visualization ===
# matplotlib and seaborn are used for creating plots and statistical visualizations.
import matplotlib.pyplot as plt
import seaborn as sns

# base64 is used to encode binary data to text (e.g., for images or files in HTML).
import base64

# io and BytesIO are used to work with streams of in-memory binary data.
import io
from io import BytesIO

# === PDF Generation ===
# reportlab is used to programmatically create PDF documents.
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# === Functional Programming Utilities ===
# functools provides decorators and higher-order functions.
from functools import wraps

# === Document Conversion ===
# docling is a custom or third-party module for converting documents.
from docling.document_converter import DocumentConverter

# === Itertools ===
# The 'itertools' module provides a set of fast, memory-efficient tools 
# for working with iterators. It is useful for creating complex iteration logic.
from itertools import combinations  # Used to generate all possible combinations of a given iterable.
import itertools  # General import to access other itertools functions if needed.

# === Math ===
# The 'math' module provides access to mathematical functions such as 
# square root, logarithms, trigonometric operations, constants like pi, and more.
import math  # Standard math functions for performing mathematical calculations.

# === itsdangerous ===
# Provides cryptographically secure tools for creating and validating time-sensitive tokens.
# Commonly used for safely signing data and generating password reset tokens.

from itsdangerous import URLSafeTimedSerializer  # Serializer that generates time-limited signed URLs.

# === werkzeug.security ===
# Offers security-related functions for password hashing and validation.
# Essential for safely storing user credentials.

from werkzeug.security import generate_password_hash  # Generates a secure hash for a given plaintext password.

# === Data Analysis and Visualization Modules (Custom) ===
# Custom modules to analyze and visualize data from CSV or Google Sheets.
from data_analysis import analyze_data
from data_analysis_googlesheets import (
    load_google_sheet_data_analysis,
    analyze_data_googlesheets
)

from visual_data import analyze_dataframe, save_dataframe_to_mongo
from visual_data_googlesheets import (
    load_google_sheet_visual_data,
    analyze_dataframe_googlesheets
)

# === Load environment variables ===
# Loading environment variables from the .env file into the application environment
load_dotenv()

# === Stripe API Keys ===
# Accessing the Stripe public and secret keys from environment variables
stripe_pub_key = os.getenv('STRIPE_PUB_KEY')
stripe_sec_key = os.getenv('STRIPE_SEC_KEY')

# === SendGrid API Configuration ===
# Accessing the SendGrid API key and sender email address
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")

# === Flask App Initialization ===
# Initializing the Flask web application
app = Flask(__name__)

# Setting the secret key for session encryption
# This key is used to secure Flask session cookies
# If not provided via environment, a new secure key is generated
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Additional salt for generating secure tokens (e.g., password reset)
app.config['SECURITY_SALT'] = os.environ.get("SECURITY_SALT", "recover-password")

# Setting how long sessions should persist — 1 hour in this case
app.permanent_session_lifetime = timedelta(hours=1)

# === Secure Cookie Settings for Flask Sessions ===
# Enhancing session cookie security
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Ensures cookies are only sent over HTTPS
    SESSION_COOKIE_SAMESITE='Lax',   # Helps protect against CSRF in most cases
    SESSION_COOKIE_HTTPONLY=True     # Prevents JavaScript from accessing cookies (protects against XSS)
)

# === MongoDB Connection Setup ===
# Retrieving the MongoDB URI from the environment
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI is not defined in the .env file")  # Fails early if URI is not set

# Initializing MongoDB client with TLS encryption (allows invalid certificates for flexibility in testing)
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)

# Accessing specific MongoDB databases
db_main = client['businessinfo']       # Main database containing core business information
db_data = client['data']               # Database for structured data analysis
db_business = client['businessdata']   # Business-related metadata and extended information
db_help = client['helpaiiqdata']       # Database for storing help/support data
db_home = client['homeaiiqdata']       # Database for storing home/dashboard related data

# === GridFS Setup for File Storage ===
# Initializing GridFS collections for handling video or large file uploads
fshome = gridfs.GridFS(db_home, collection="videos")
fshelp = gridfs.GridFS(db_help, collection="videos")

# === File Upload Folder Configuration ===
# Directory used to store uploaded files (such as CSVs)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)  # Creates the upload folder if it doesn't already exist

# === SMTP Configuration for Email Sending ===
# SMTP credentials for sending account-related emails (activation, verification, etc.)
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# === Business ID Pattern Validation ===
# Regular expression used to validate business IDs:
# Must be alphanumeric and between 1 and 20 characters
business_id_pattern = re.compile(r'^[a-zA-Z0-9]{1,20}$')

# === Stripe Initialization ===
# Setting the secret API key for Stripe transactions
stripe.api_key = os.getenv('STRIPE_SEC_KEY')

# === reCAPTCHA Configuration ===
# Site and secret keys for integrating Google reCAPTCHA (used to prevent bots)
site_key = os.getenv('RECAPTCHA_KEY_SITE')
secret_key = os.getenv('RECAPTCHA_SECRECT_KEY_SITE')  # Note: Typo in variable name "SECRECT" should be "SECRET"?

# === Google Sheets Access ===
# 'gspread' is a Python library for interacting with Google Sheets via the Google Sheets API.
# It allows reading, writing, and modifying spreadsheet data programmatically.
import gspread

# 'Credentials' from 'google.oauth2.service_account' is used to authenticate 
# with Google APIs using a service account (recommended for server-side applications).
from google.oauth2.service_account import Credentials

# === Regular Expressions ===
# 're' is the regular expression module in Python, used for pattern matching, 
# searching, and text processing based on defined patterns.
import re

# Define Google service account credentials
SERVICE_ACCOUNT_INFO = {
    <your here>
    }

# Define scopes (permissions) for reading from Google Sheets and Drive
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly",
        "https://www.googleapis.com/auth/drive.readonly"]

def login_required(f):
    """
    Decorator to ensure the user is authenticated and the session is secure before accessing a route.

    Verifies:
    - User is logged in (session contains 'business_id' and 'username')
    - Session contains a valid ID
    - User-Agent hasn't changed
    - IP hasn't changed
    - MongoDB connection is alive

    If any check fails, the session is cleared and user is redirected to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for login credentials
        if not session.get('business_id') or not session.get('username'):
            print("You need to be logged in to access this page.")
            flash("You need to be logged in to access this page.", 'warning')
            return redirect(url_for('login'))

        # Check MongoDB connection
        try:
            client.server_info()  # Verifies MongoDB connection
        except Exception as e:
            print(f"❌ Error connecting to MongoDB: {str(e)}")
            flash("Internal server error. Please try again later.", 'danger')
            return redirect(url_for('login'))

        # Check session integrity (User-Agent & IP Address)
        if not session.get('id'):
            session['id'] = os.urandom(16).hex()  # Secure random ID on login

        current_user_agent = request.headers.get('User-Agent')
        current_ip = request.remote_addr

        # Store or validate User-Agent
        if not session.get('user_agent'):
            session['user_agent'] = current_user_agent
        elif session['user_agent'] != current_user_agent:
            session.clear()
            print("Session invalidated: User-Agent changed.")
            flash("Session invalidated: User-Agent changed.", 'danger')
            abort(403, description="Session invalidated: User-Agent changed.")

        # Store or validate IP address
        if not session.get('ip'):
            session['ip'] = current_ip
        elif session['ip'] != current_ip:
            session.clear()
            print("Session invalidated: IP address changed.")
            flash("Session invalidated: IP address changed.", 'danger')
            abort(403, description="Session invalidated: IP address changed.")

        return f(*args, **kwargs)
    
    return decorated_function

# Error handler function
@app.errorhandler(500)
def errorhandler(e):
    """
    Handles server errors and returns an error page.
    """
    print(f"Internal error server: {str(e)}")
    flash("Internal error server.", 'danger')
    
    # Redirecionar para uma página de erro, se houver uma
    return redirect(url_for("error"))

# Function to check if a user's credentials are valid in MongoDB
def check_user_in_mongo(business_id, username, password):
    """
    Verifies if the user's credentials (username and password) are valid in MongoDB.
    
    Args:
    - business_id (str): The business identifier for the collection.
    - username (str): The username of the user.
    - password (str): The password of the user.

    Returns:
    - bool: True if the user is found with the correct credentials, otherwise False.
    """
    user_collection = db_business[business_id]  # Access the collection based on the Business ID
    user = user_collection.find_one({"username": username, "password": password})  # Search by username and password
    return user is not None  # Return True if the user is found, otherwise False

# Function to check if a user is an admin in MongoDB
def check_user_is_admin(business_id, username_or_email):
    """
    Verifies if a user is an admin in the MongoDB database.
    
    Args:
    - business_id (str): The business identifier for the collection.
    - username_or_email (str): The username or email of the user to check.

    Returns:
    - bool: True if the user is an admin, otherwise False.
    """

    try:
        business_collection = db_business[business_id]  # Access business collection

        # Check if the input is an email using regex
        is_email = re.match(r"[^@]+@[^@]+\.[^@]+", username_or_email)

        # Define the query to search by username or email
        query = {"e-mail": username_or_email} if is_email else {"username": username_or_email}

        # Search the collection for the user
        user = business_collection.find_one(query)

        # Check if the user exists and if their role is 'admin'
        if user and user.get('role') == 'admin':
            return True  # User is an admin
        else:
            return False  # User is not an admin

    except Exception as e:
        print(f"Error while checking admin status: {str(e)}")
        flash(f"Error while checking admin status: {str(e)}", 'warning')
        return False

# Function to send an email with the account activation link
def send_email(to_email, business_id, username, password, activation_link):
    """
    Sends an account activation email with a link to the user's email address.

    Args:
    - to_email (str): The recipient's email address.
    - business_id (str): The business identifier.
    - username (str): The username of the user.
    - password (str): The user's password.
    - activation_link (str): The URL link to activate the user's account.

    Returns:
    - bool: True if the email is sent successfully, otherwise False.
    """

    subject = "Account Activation - AIIQData Team"
    body = f"""
    <html>
    <body>
        <p>Hello, <b>{username}</b>!</p>
        <br>
        <p>Thank you for registering with <b>AIIQData</b>. To activate your account, click the link below:</p>
        <p><a href="{activation_link}" style="color: blue; font-size: 12px;">Activate my account</a></p>
        <p>If the link does not work, try to put the following link in your browser: {activation_link}</p>
        <p>If you did not request this registration, please ignore this e-mail.</p>
        <p>Your credencials are:</p>
        <p>- Business ID: {business_id}</p>
        <p>- Username: {username} or {to_email}</p>
        <p>- Password: {password}</p>
        <br><br>
        <p style="font-size: 14px; color: #555;">
            Best regards,<br>
            <strong>The AIIQData Team</strong><br>
            <em>Empowering AI-driven decisions</em><br><br>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." width="30" height="30" alt="AIIQData Logo"/>
        </p>
    </body>
    </html>
    """
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=body
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
      
        print(f"User added. Email with credencials sent to {to_email} successfully! | Status Code: {response.status_code}")
        flash(f"User added. Email with credencials sent to {to_email} successfully!", 'warning')
        return True
    
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash(f"Error sending email: {str(e)}", 'warning')
        return False

# Function to send an email when a new user is added to the business
def send_email_add_user(to_email, business_id, username, password):
    """
    Sends an email with user credentials when they are added to the system.

    Args:
    - to_email (str): The recipient's email address.
    - business_id (str): The business identifier.
    - username (str): The username of the new user.
    - password (str): The password of the new user.

    Returns:
    - bool: True if the email is sent successfully, otherwise False.
    """

    subject = "Access Credentials - Business AI"
    body = f"""
    <html>
    <body>
        <p>Hello, <b>{username}</b>!</p>
        <br>
        <p>You have been added to AIIQData. Your access credentials are:</p>
        <p>- Business ID: {business_id}</p>
        <p>- Username: {username}</p>
        <p>- Password: {password}</p>
        <p>Please log in, if you want to change your password contact your admin</p>
        <br><br>
        <p style="font-size: 14px; color: #555;">
            Best regards,<br>
            <strong>The AIIQData Team</strong><br>
            <em>Empowering AI-driven decisions</em><br><br>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." width="30" height="30" alt="AIIQData Logo"/>
        </p>
    </body>
    </html>
    """
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=body
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        
        print(f"Email sent to {to_email} successfully! | Status Code: {response.status_code}")
        flash(f"Email sent to {to_email} successfully!", 'warning')
        return True
    
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash(f"Error sending email: {str(e)}", 'warning')
        return False
    
# Function to send an email with the recover activation link
def send_email_recover_password(to_email, business_id, username, activation_link):
    """
    Sends an recover password email.

    """

    subject = "Account Recover Password - AIIQData Team"
    body = f"""
    <html>
    <body>
        <p>Hello, <b>{username}</b>!</p>
        <br>
        <p>To recover your account, click the link below:</p>
        <p><a href="{activation_link}" style="color: blue; font-size: 12px;">Recover my account</a></p>
        <p>If the link does not work, try to put the following link in your browser: {activation_link}</p>
        <p>If you did not request this registration, please ignore this e-mail.</p>
        <p>Your credencials are:</p>
        <p>- Business ID: {business_id}</p>
        <p>- Username: {username}</p>
        <p>- E-mail: {to_email}</p>
        <br><br>
        <p style="font-size: 14px; color: #555;">
            Best regards,<br>
            <strong>The AIIQData Team</strong><br>
            <em>Empowering AI-driven decisions</em><br><br>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." width="30" height="30" alt="AIIQData Logo"/>
        </p>
    </body>
    </html>
    """
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=body
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
      
        print(f"Email with step by step for recover password sent to {to_email} successfully! | Status Code: {response.status_code}")
        flash(f"Email with step by step for recover password sent to {to_email} successfully!", 'warning')
        return True
    
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash(f"Error sending email: {str(e)}", 'warning')
        return False

# Function to check if a file extension is allowed
# def allowed_file(filename):
#     """
#     Checks if the file extension is allowed for upload.
    
#     Args:
#     - filename (str): The name of the file being uploaded.

#     Returns:
#     - bool: True if the file extension is allowed, otherwise False.
#     """

#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_plan(business_id):
    """ Get the user's plan based on the business_id and return the plan details. If no plan exists, assume 'Free'. """

    user_data = db_business['users'].find_one({"business_id": business_id}, {"plan": 1}) # Get the user's plan name
    plan_name = user_data.get("plan", "Free") if user_data else "Free"
    plan_details = db_business['plans'].find_one({"plan": plan_name}) # Get the plan details from the 'plans' collection
    return plan_details if plan_details else db_business['plans'].find_one({"plan": "free"}) # If the plan is not found, return the 'Free' plan details by default

def check_plan_status(business_collection, username):
    """Verifies if the user’s plan has expired and updates to 'free' if necessary."""
    user_data = business_collection.find_one({"username": username})

    if not user_data:
        print("Error: User not found.")
        flash("Error: User not found.", 'error')
        return

    validity_date = user_data.get("validity_date") # Check plan validity

    if validity_date and validity_date.tzinfo is None:  
        # Se for naive, forçar UTC
        validity_date = validity_date.replace(tzinfo=timezone.utc)

    if validity_date and datetime.now(timezone.utc) > validity_date:
        # If the plan has expired, change to the free plan
        business_collection.update_one(
            {"username": username},
            {"$set": {"plantype": "free"}}
        )
        print("Your plan has expired. You have been moved to the Free plan.")
        flash("Your plan has expired. You have been moved to the Free plan.", 'info')

def generate_error_image(error_message):
    """
    Generates an image containing a formatted error message.

    This function is useful for applications that need to return errors
    as images (e.g., embedding visual error feedback in a web UI or chart).

    Parameters:
    -----------
    error_message : str
        The error message to be displayed on the image.

    Returns:
    --------
    BytesIO
        A BytesIO object containing the PNG image with the rendered error message.
    """

    fig, ax = plt.subplots(figsize=(8, 2)) # Create a matplotlib figure and axis with a fixed size (8 inches wide, 2 inches tall)

    # Display the error message in the center of the image with red font
    ax.text(
        0.5, 0.5,                  # Position at the center of the axes (x=50%, y=50%)
        error_message,             # The actual error message text
        fontsize=12,               # Font size for readability
        color='red',               # Red color to emphasize the error
        ha='center',               # Horizontal alignment to center
        va='center',               # Vertical alignment to center
        wrap=True                  # Automatically wrap long text
    )

    ax.axis('off') # Remove axis lines and ticks to produce a clean image
    img = io.BytesIO() # Create an in-memory binary stream to hold the image data
    plt.savefig(img, format='png', bbox_inches='tight') # Save the figure as a PNG into the BytesIO buffer
    img.seek(0) # Rewind the buffer to the beginning so it can be read later
    plt.close() # Close the plot to free up memory
    return base64.b64encode(img.getvalue()).decode('utf-8') # Return the image with the message error

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_SALT'])

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_SALT'], max_age=expiration)
        return email
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None

# Registration route with email sending
@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Handles user registration, storing data in MongoDB and sending an activation email. """
    if request.method == 'GET':
        return render_template('register.html', site_key=site_key)
    
    session.clear()  # Limpa a sessão antes de iniciar uma nova
    recaptcha_response = request.form.get('g-recaptcha-response')
    verify_url = "https://www.google.com/recaptcha/api/siteverify"

    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }

    response = requests.post(verify_url, data=payload)
    result = response.json()
    
    if not result.get('success'):
        print("Human verification failed. Please try again.")
        flash("Human verification failed. Please try again.", 'error')
        return render_template('login.html', site_key=site_key)
    
    if request.method == 'POST':
        business_id = request.form['business_id']  # Get business_id from the form
        email = request.form['email']  # Get email from the form
        password = request.form['password']  # Get password from the form

        try:
            # Validate the business ID (add your validation logic here)
            if not business_id:
                print("Invalid Business ID!")
                flash("Invalid Business ID!", 'danger')
                return render_template('register.html')
            
            # Check if the business ID already exists in the database
            if business_id in db_business.list_collection_names():
                print("Business ID already exists. Please choose another one.")
                flash("Business ID already exists. Please choose another one.", 'danger')
                return render_template('register.html')

            # Access the business collection
            business_collection = db_business[business_id]
            data_collection = db_business['data']

            # Check if an admin already exists for this Business ID
            if business_collection.find_one({"username": f"{business_id}admin"}):
                print("Admin already registered for this Business ID.")
                flash("Admin already registered for this Business ID.", 'danger')
                return render_template('register.html')

            # Generate activation token
            activation_token = secrets.token_urlsafe(32)

            # Insert the new admin user into the collection
            business_collection.insert_one(
                {
                "username": f"{business_id}admin",
                "email": email,
                "password": password,
                "plantype": "free",
                "role": "admin",
                "created_at": datetime.now(timezone.utc),
                "activation_token": activation_token,
                "is_active": False,
                "info_database": f"{business_id}info", 
                "news_database": f"{business_id}news",
                "csv_database": f"{business_id}csv",
                "notebook_database": f"{business_id}notebook",
                "chatbot_usage": 0,
                "data_analisys_usage": 0,
                "payment_info": {
                    "transaction_id": None,
                    "amount": None,
                    "currency": None,
                    "status": None,
                    "payment_date": None
                    }
                })
            
            data_collection.insert_one(
                {
                "business_id": business_id,
                "usernameadmin": f"{business_id}admin",
                "info_database": f"{business_id}info", 
                "news_database": f"{business_id}news",
                "csv_database": f"{business_id}csv"
                })

            # Send an activation email with a link
            activation_link = f"https://aiiqdata.com/activate/{activation_token}"
            subject = "Account Activation - AIIQData"
            body = f"""
            Hello, {business_id}admin!
            
            Thank you for registering with AIIQData. To activate your account, click the link below:
            
            {activation_link}
            
            If you did not request this registration, please ignore this email.
            """

            # Try sending the email with the activation link
            if send_email(email, business_id, f"{business_id}admin", password, activation_link):
                print("Registration successful! Please check your email to activate your account.")
                flash("Registration successful! Please check your email to activate your account.", 'success')
            else:
                print("Error sending activation email. Please contact support.")
                flash("Error sending activation email. Please contact support.", 'danger')

            return redirect(url_for('register'))

        except Exception as e:
            print(f"Error registering user: {str(e)}")
            flash(f"Error registering user: {str(e)}", 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

# Route to activate the account via token
@app.route('/activate/<token>')
def activate_account(token):
    """ Activates the user account using the provided token. """
    # Iterate through collections to find the user by token
    for collection_name in db_business.list_collection_names():
        collection = db_business[collection_name]

        user = collection.find_one({"activation_token": token})
        
        if user:
            # Verificação para garantir que o token é o esperado
            if user['activation_token'] == token:

                # Activate user account
                update_result = collection.update_one(
                    {"activation_token": token},
                    {"$set": {"is_active": True}, "$unset": {"activation_token": ""}}
                )

                if update_result.matched_count > 0:
                    print("Account activated successfully! You can now log in.")
                    flash("Account activated successfully! You can now log in.", 'success')
                    return redirect(url_for('login'))
                    
                else:
                    print("Error while activating account. Please try again.")
                    flash("Error while activating account. Please try again.", 'danger')
                    return redirect(url_for('login'))
    
    print("Invalid or expired token.")
    flash("Invalid or expired token.", 'danger')
    return redirect(url_for('login'))

@app.route('/')
def home():
    file_doc = fshome.find_one()  # Pode passar filtros, se quiser
    video_filename1 = file_doc.filename if file_doc else None

    user_collection_home = db_home['homeaiiqdata']

    text1 = user_collection_home.find_one({"page": "home", "field": "text1"})
    text2 = user_collection_home.find_one({"page": "home", "field": "text2"})
    text3 = user_collection_home.find_one({"page": "home", "field": "text3"})
    text4 = user_collection_home.find_one({"page": "home", "field": "text4"})
    text5 = user_collection_home.find_one({"page": "home", "field": "text5"})
    text6 = user_collection_home.find_one({"page": "home", "field": "text6"})
    text7 = user_collection_home.find_one({"page": "home", "field": "text7"})
    text8 = user_collection_home.find_one({"page": "home", "field": "text8"})
       
    # Redirect to the home page
    return render_template('home.html', video_filename1=video_filename1, text1=text1, text2=text2, text3=text3, 
                           text4=text4, text5=text5, text6=text6, text7=text7, text8=text8)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login by verifying credentials, checking account activation,
    validating reCAPTCHA, and managing session state.

    GET: Render the login form along with the reCAPTCHA site key.
    POST: Validate input fields and reCAPTCHA, authenticate the user based on
    username/email and password, and start a session if credentials are valid.

    Uses MongoDB collections dynamically based on the 'business_id' field.
    """
    if request.method == 'GET':
        # Render login form and inject reCAPTCHA site key into template
        return render_template('login.html', site_key=site_key)
    
    session.clear()  # Clear session data at the beginning of a new login attempt
    # Retrieve user input from form submission
    business_id = request.form.get('business_id')
    username_or_email = request.form.get('username')
    password = request.form.get('password')
    recaptcha_response = request.form.get('g-recaptcha-response') # Retrieve reCAPTCHA response token from form
    verify_url = "https://www.google.com/recaptcha/api/siteverify" # Validate reCAPTCHA to prevent bots from logging in
    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post(verify_url, data=payload)
    result = response.json()
    
    # If reCAPTCHA validation fails, notify the user
    if not result.get('success'):
        print("Human verification failed. Please try again.")
        flash("Human verification failed. Please try again.", 'error')
        return render_template('login.html', site_key=site_key)

    # Check if all required fields are filled
    if not business_id or not username_or_email or not password:
        print("All fields are required.")
        flash("All fields are required.", 'danger')
        return render_template('login.html', site_key=site_key)

    try:
        business_collection = db_business[business_id] # Dynamically access the MongoDB collection for the given business
        is_email = re.match(r"[^@]+@[^@]+\.[^@]+", username_or_email) # Check if input is an email (basic validation using regex)
        query = {"email": username_or_email} if is_email else {"username": username_or_email} # Create query to match user by email or username + password
        user = business_collection.find_one({**query, "password": password})

        if user:
            # Check if the account is activated
            if not user.get('is_active', False):
                print(f"Your account is not activated. Please check your email to activate your account.")
                flash(f"Your account is not activated. Please check your email to activate your account.", 'danger')
                return render_template('login.html', site_key=site_key)
            
            # If valid and active user, start a persistent session
            session.permanent = True
            session['username'] = username_or_email
            session['business_id'] = business_id
            check_plan_status(business_collection, username_or_email) # Perform post-login checks (e.g., plan validity)

            return redirect(url_for('index'))
        
        else:
            # Invalid credentials: show error and reload login form
            print(f"Login failed: Invalid credentials for {username_or_email} in {business_id}")
            flash(f"Login failed: Invalid credentials for {username_or_email} in {business_id}", 'danger')
            return render_template('login.html', site_key=site_key)
    
    except Exception as e:
        # Handle unexpected errors (e.g., database access)
        print(f"An error occurred during login: {str(e)}")
        flash(f"An error occurred during login: {str(e)}", 'danger')
        return render_template('login.html', site_key=site_key)

# Route for password recovery – handles both GET (form rendering) and POST (form submission)
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    """
    Handle the password recovery process.

    GET: Render the password recovery form.
    POST: Validate the input fields (business_id, username, email), search for the user in the
    appropriate MongoDB collection, generate a secure token, and send a password reset email
    containing a unique recovery link.

    Flash messages and redirections are used for feedback and flow control.
    """
    # Render the recovery form if the method is GET
    if request.method == 'GET':
        return render_template('recover_password.html')

    session.clear() # Clear any existing session data (for security and clean flow)
    # Retrieve form data submitted by the user
    business_id = request.form.get('business_id') 
    username = request.form.get('username')
    email = request.form.get('email')

    # Validate that all fields are filled
    if not business_id or not username or not email:
        print("Please fill out all fields.")
        flash("Please fill out all fields.", "warning")
        return redirect(url_for('recover_password'))
    
    try:
        collection = db_business[business_id] # Attempt to access the user collection for the given business_id

    except Exception as e:
        # Handle invalid business_id or database errors
        print(f"Error accessing the collection: {e}")
        flash("Invalid Business ID.", "danger")
        return redirect(url_for('recover_password'))

    # Look for a user with matching username and email
    user = collection.find_one({
        "username": username,
        "email": email
    })

    # If no user found, notify the user
    if not user:
        print("No user found with that username and email in the given business ID.")
        flash("No user found with that username and email in the given business ID.", "danger")
        return redirect(url_for('recover_password'))

    token = generate_token(email) # Generate secure token for password reset
    reset_url = url_for('reset_password', token=token, business_id=business_id, username=username, email=email, _external=True) # Create full URL for password reset, including the token and user data

    # Send password recovery email to the user with the reset link
    send_email_recover_password(
        to_email=email,
        business_id=business_id,
        username=username,
        activation_link=reset_url
    )

    # Notify the user that the link has been sent
    print("Recovery link sent to your email.")
    flash("Recovery link sent to your email.", "info")

    return redirect(url_for('login'))

# Route to handle the actual password reset using a token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Handle the password reset process after receiving the reset link with a secure token.

    GET: Render the password reset form.
    POST: Verify the token, validate user data (business_id, username), and update the password in the database.

    Flash messages are used to indicate success or errors, and the user is redirected accordingly.
    """
    # Render password reset form if the method is GET
    if request.method == 'GET':
        return render_template('reset_password.html', token=token)

    # Retrieve data sent through the URL (query parameters)
    business_id = request.args.get('business_id') 
    username = request.args.get('username')
    email = verify_token(token) # Validate the token and retrieve the email from it

    # Ensure all required information is available
    if not all([business_id, username, email]):
        print("Missing required data.")
        flash("Missing required data.", "warning")
        return redirect(url_for('recover_password'))

    new_password = request.form.get('password') # Get new password submitted by user

    try:
        # Update the password in the database
        result = db_business[business_id].update_one(
            {"username": username, "email": email},
            {"$set": {"password": new_password}} 
        )

        # Check if the password was actually updated
        if result.modified_count == 0:
            print("User not found or password not updated.")
            flash("User not found or password not updated.", "danger")
        else:
            print("Password reset successful.")
            flash("Password reset successful.", "success")

    except Exception as e:
        print(f"Error updating password: {e}")
        flash(f"Error updating password: {e}", "danger")

    return redirect(url_for('login'))

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    """
    Handles requests for the index page. Verifies user authentication and retrieves user data.
    If the user is not authenticated, redirects to the login page.
    """
    user_name = session.get('username')  # Retrieve the username from the session
    business_id = session.get('business_id')  # Retrieve the business ID from the session
    is_admin = False  # Default to non-admin status

    # Redirect to login if the user is not authenticated
    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'warning')
        return redirect(url_for('login'))

    # Redirect to login if business_id is missing
    if not business_id:
        print("business_id not found in session. Redirecting to login.")
        flash("business_id not found in session. Redirecting to login.", 'warning')
        return redirect(url_for('login'))

    try:        
        # Verify if the business collection exists before accessing it
        if business_id not in db_business.list_collection_names():
            return redirect(url_for('login'))

        business_collection = db_business[business_id]
        user = business_collection.find_one({"username": user_name})

        if user:
            # Check if the user has admin privileges
            if user.get('role') == 'admin':
                is_admin = True

            # Fetch the specific plans from the 'plans' collection
            plans_collection = db_business['plans']
            standard_plan = plans_collection.find_one({"plan": "standard"}, {"_id": 0})
            professional_plan = plans_collection.find_one({"plan": "professional"}, {"_id": 0})

            # Fetch news from the 'news' collection
            news_collection = db_business[f'{business_id}news']  # Assuming there's a 'news' collection
            news = list(news_collection.find({}, {"_id": 0}).sort([("date", -1)]))  # Sorting by date, most recent first

            return render_template('index.html', user_name=user_name, is_admin=is_admin, user_data=user, business_id=business_id, standard_plan=standard_plan, professional_plan=professional_plan, news=news)
        
        else:
            return redirect(url_for('login'))

    except Exception as e:
        print(f"Error connecting or fetching user from MongoDB: {str(e)}")
        flash(f"Error connecting or fetching user from MongoDB: {str(e)}", 'warning')
        return redirect(url_for('index'))
    
# Admin route to manage users
@app.route('/admin')
@login_required
def admin():
    """
    Handles requests for the admin page. 
    Verifies if the user is authenticated and has admin privileges.
    If the user is an admin, retrieves a list of users for management.
    """
    user_name = session.get('username')  # Retrieve username from session
    business_id = session.get('business_id')  # Retrieve business ID from session

    # Redirect to login if the user is not authenticated
    if not user_name or not business_id:
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]

    try:
        
        # Verify if the business collection exists before accessing it
        if business_id not in db_business.list_collection_names():
            print(f"Invalid business_id: {business_id}.")
            flash(f"Invalid business_id: {business_id}.", 'error')
            return redirect(url_for('login'))
        
        # Retrieve user data to verify admin role
        user = business_collection.find_one({"username": user_name})

        if user and user.get('role') == 'admin':
            is_admin = True

            # Retrieve a list of users excluding the admin
            users = list(business_collection.find(
                {"username": {"$ne": user_name}}, 
                {"_id": 0, "username": 1, "email": 2, "password": 3}
            ))
            
            user_admin_info = list(business_collection.find(
                {"role": "admin"},
                {"_id": 0, "username": 1, "email": 2, "password": 3, "plantype": 4, "role": 5, "is_active": 7, "chatbot_usage": 11, "data_analisys_usage": 12, "validity_date": 14}
            ))

            # Fetch user data to avoid errors if it does not exist
            user_data = business_collection.find_one({"username": user_name})
            
            if user_data is None:
                print(f"No user data found for {user_name}.")
                flash(f"No user data found for {user_name}.", 'warning')
                user_data = {}  # Prevents errors when accessing data

            # Retrieve plan type safely, defaulting to "N/A" if not found
            plan_type = user_data.get("plantype", "N/A")

            return render_template('admin.html', user_name=user_name, users=users, user_admin_info=user_admin_info, is_admin=is_admin, user_data=user, business_id=business_id)
        
        else:
            print(f"User {user_name} is not an admin. Redirecting to the home page.")
            flash(f"User {user_name} is not an admin. Redirecting to the home page.", 'warning')
            return redirect(url_for('index'))

    except Exception as e:
        print(f"Error fetching admin user data: {str(e)}")
        flash(f"Error fetching admin user data: {str(e)}", 'error')
        return redirect(url_for('index'))

# Route to add a new user
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'error')
        return redirect(url_for('login'))

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash("User is not an admin. Action not allowed.", 'error')
        return redirect(url_for('index'))

    # Access the corresponding collection for the given Business ID
    business_collection = db_business[business_id]

    # Verificar o plano do usuário
    plan = get_user_plan(business_id)  # Função que retorna o plano do usuário

    if plan is None:
        print("Invalid plan or not found.")
        flash("Invalid plan or not found.", 'danger')
        return redirect(url_for('index'))

    # Contar o número de usuários (considerando que cada usuário é um documento na coleção)
    current_users = business_collection.count_documents({"role": "user"})  # Contando todos os documentos (usuários)
    
    if current_users >= plan['limit_users']:
        print("You have reached the maximum number of users for your plan.")
        flash("You have reached the maximum number of users for your plan.", 'danger')
        return redirect(url_for('admin'))

    try:
        # Get the admin user's data, including payment_info
        admin_data = business_collection.find_one({"username": user_name})
        if not admin_data:
            print("Admin not found. Operation canceled.")
            flash("Admin not found. Operation canceled.", 'error')
            return redirect(url_for('admin'))
        
        # Ensure to use both 'plantype' and 'payment_info' from the admin user
        admin_plan = admin_data.get("plantype", "free")  # Default to 'free' if not specified
        admin_payment_info = admin_data.get("payment_info", {
            "transaction_id": None,
            "amount": None,
            "currency": None,
            "status": None,
            "payment_date": None
        })  # Default to empty payment_info if not present

        # Get the new user's data from the form
        new_user_data = {
            '_id': str(bson.ObjectId()),  # Generate an ObjectId to maintain the MongoDB standard
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'plantype': admin_plan,  # Use the same plan type as the admin
            'role': 'user',  # Ensure the new user is not an admin
            'created_at': datetime.now(timezone.utc),
            'is_active': True,  # Always active by default
            "info_database": f"{business_id}info",
            "payment_info": admin_payment_info
            }

        # Insert the new user into the collection
        business_collection.insert_one(new_user_data)

        # Send an email with the new user's credentials
        send_email_add_user(new_user_data['email'], business_id, new_user_data['username'], new_user_data['password'])
        print(f"New user {new_user_data['username']} created successfully.")
        flash(f"New user {new_user_data['username']} created successfully.", 'success')

        return redirect(url_for('admin'))

    except Exception as e:
        print(f"Error adding user: {str(e)}")
        flash(f"Error adding user: {str(e)}", "error")
        return redirect(url_for('admin'))

# Route to delete a user
@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", "error")
        return redirect(url_for('login'))
    
    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    # If the user is not an admin, redirect to the admin page
    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash("User is not an admin. Action not allowed.", 'error')
        return redirect(url_for('index'))

    username_to_delete = request.form.get('username')

    if not username_to_delete:
        print("No user selected for deletion.")
        flash("No user selected for deletion.", 'error')
        return redirect(url_for('admin'))  # Redirect to user management page if no user is selected

    business_collection = db_business[business_id]

    try:

        if username_to_delete == user_name:
            print("Admin user cannot be deleted.")
            flash("Admin user cannot be deleted.", 'error')
            return redirect(url_for('admin'))  # Prevent the deletion of the admin user

        # Fetch the user to delete
        user_to_delete = business_collection.find_one({"username": username_to_delete})

        if not user_to_delete:
            print("User not found.")
            flash("User not found.", 'error')
            return redirect(url_for('admin'))  # Redirect if user is not found

        # Delete the user from the collection
        business_collection.delete_one({"username": username_to_delete})
        print(f"User {username_to_delete} deleted successfully.")
        flash(f"User {username_to_delete} deleted successfully.", 'success')

    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        flash(f"Error deleting user: {str(e)}", 'error')
        return redirect(url_for('admin'))

    return redirect(url_for('admin'))
    
@app.route('/add_question_and_answer', methods=['POST'])
@login_required
def add_question_and_answer():
    # Check if the user is authenticated and if they are an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    # If the user is not authenticated, redirect to the login page
    if not user_name:
        print("You must be logged in to add a question and answer.")
        flash("You must be logged in to add a question and answer.", 'warning')
        return redirect(url_for('login'))

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    # If the user is not an admin, redirect to the admin page
    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))

    # Access the collection specific to the Business ID provided
    info_collection = db_business[f'{business_id}info']  # Collection for infos of the specific business_id

    # Buscar o plano do usuário no MongoDB dentro da coleção específica do business_id
    business_collection = db_business[business_id]  # Coleção do negócio
    business_data = business_collection.find_one({}, {"plantype": 1})  # Buscar apenas o campo 'plan'

    # Verificar o plano do usuário
    plan = get_user_plan(business_id)  # Função que retorna o plano do usuário

    if plan is None:
        print("Invalid or missing plan.")
        flash("Invalid or missing plan.", 'danger')
        return redirect(url_for('index'))
    
    # Contar o número de usuários (considerando que cada usuário é um documento na coleção)
    current_users = business_collection.count_documents({"type": "question_answer"})  # Contando todos os documentos (usuários)
    
    if current_users >= plan['limit_users']:
        print("You have reached the maximum number of users for your plan.")
        flash("You have reached the maximum number of users for your plan.", 'danger')
        return redirect(url_for('admin'))

    if not business_data or "plantype" not in business_data:
        print("Plan information not found. Please contact support.")
        flash("Plan information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))

    user_plan = business_data["plantype"]

    # Buscar os limites do plano na coleção 'plans', que está separada
    plans_collection = db_business["plans"]  # Pegamos a coleção `plans`
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_questions": 1})  # Buscar limite

    if not plan_data or "limit_questions" not in plan_data:
        print("Plan limits not found. Please contact support.")
        flash("Plan limits not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))

    max_entries = plan_data["limit_questions"]
    current_count = info_collection.count_documents({})

    if current_count >= max_entries:
        print(f"Limit reached for plan '{user_plan}' ({max_entries} entries). Cannot add more. Upgrade to add more entries.")
        flash(f"Limit reached for plan '{user_plan}' ({max_entries} entries). Cannot add more. Upgrade to add more entries.", 'danger')
        return redirect(url_for('admin'))

    try:
        # Capturar dados do formulário
        question = request.form.get('question')
        answer = request.form.get('answer')
        procedure_path = request.form.get('procedure_path')

        if not question or not answer:
            print("Question and Answer fields cannot be empty.")
            flash("Question and Answer fields cannot be empty.", 'warning')
            return redirect(url_for('admin'))

        # Capture form data for the new info entry
        info_data = {
            'question': question,
            'answer': answer,
            'procedure_path': procedure_path,
            'id_database': 'businessdata',
            'business_id': business_id,
            'added_by': user_name,
            'type': "answer_question",
            'created_at': datetime.now(timezone.utc)
        }

        # Insert the info data into MongoDB
        info_collection.insert_one(info_data)
        print(f"Question successfully added: {info_data['question']}")
        flash("Question and answer added successfully!", 'success')

    except Exception as e:
        print(f"Error while adding question: {str(e)}")
        flash(f"Error while adding question: {str(e)}", 'danger')
        return redirect(url_for('admin'))

    return redirect(url_for('admin'))

@app.route('/add_document', methods=['POST'])
@login_required
def add_document():
    # Check if the user is authenticated and if they are an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    # If the user is not authenticated, redirect to the login page
    if not user_name:
        print("You must be logged in to add a document.")
        flash("You must be logged in to add a document.", 'warning')
        return redirect(url_for('login'))

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    # If the user is not an admin, redirect to the admin page
    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))
    
    # Verifica se o arquivo foi enviado corretamente
    if 'fileInput' not in request.files:
        print("No file uploaded.")
        flash("No file uploaded.", 'danger')
        return redirect(url_for('admin'))

    file = request.files['fileInput']

    if file.filename == '':
        print("Invalid file name.")
        flash("Invalid file name.", 'danger')
        return redirect(url_for('admin'))

    info_collection = db_business[f'{business_id}info']  # Collection for infos of the specific business_id # Access the collection specific to the Business ID provided
    business_collection = db_business[business_id]  # Business collection # Retrieve the user's plan from MongoDB within the specific business_id collection
    business_data = business_collection.find_one({}, {"plantype": 1})  # Retrieve only the 'plan' field
    plan = get_user_plan(business_id) # Function that returns the user's plan # Check the user's plan

    if plan is None:
        print("Invalid or missing plan.")
        flash("Invalid or missing plan.", 'danger')
        return redirect(url_for('index'))

    current_users = business_collection.count_documents({"type": "document"}) # Counting all documents (users) # Count the number of users (assuming each user is a document in the collection)
    
    if current_users >= plan['limit_users']:
        print("You have reached the maximum number of users for your plan.")
        flash("You have reached the maximum number of users for your plan.", 'danger')
        return redirect(url_for('admin'))

    if not business_data or "plantype" not in business_data:
        print("Plan information not found. Please contact support.")
        flash("Plan information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))

    user_plan = business_data["plantype"]

    # Buscar os limites do plano na coleção 'plans', que está separada
    plans_collection = db_business["plans"]  # Pegamos a coleção `plans`
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_docs": 1})  # Buscar limite
    
    try:
        intro = request.form.get('intro')

        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, file.filename)  # Caminho correto para qualquer SO
        file.save(temp_path)

        converter = DocumentConverter()
        doc_markdown = converter.convert(temp_path)
        
        if not doc_markdown or not hasattr(doc_markdown, 'document') or not hasattr(doc_markdown.document, 'export_to_markdown'):
            print("Failed to convert document to markdown or no markdown available.")
            flash("Failed to convert document to markdown or no markdown available.", 'danger')
            return redirect(url_for('admin'))
        
        markdown_content = doc_markdown.document.export_to_markdown()
        if not markdown_content:
            print("Markdown content is empty.")
            flash("Markdown content is empty.", 'danger')
            return redirect(url_for('admin'))

        # Capture form data for the new info entry
        info_data = {
            'question': intro,
            'answer': markdown_content,
            'procedure_path': 'None',
            'id_database': 'businessdata',
            'business_id': business_id,
            'added_by': user_name,
            'type': "document",
            'created_at': datetime.now(timezone.utc)
        }

        # Insert the info data into MongoDB
        info_collection.insert_one(info_data)
        print(f"Document added successfully!: {info_data['question']}")
        flash("Document added successfully!", 'success')

        os.remove(temp_path)

        print("Document saved successfully!")    
        flash("Document saved successfully!", 'success')
        return redirect(url_for('admin'))

    
    except Exception as e:
        print(f"Error processing the document: {str(e)}")
        flash(f"Error processing the document: {str(e)}", 'danger')
        return redirect(url_for('admin'))
    
@app.route('/add_news', methods=['POST'])
@login_required
def add_news():
    # Check if the user is authenticated and if they are an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    # If the user is not authenticated, redirect to the login page
    if not user_name:
        print("You must be logged in to add a new.")
        flash("You must be logged in to add a new.", 'warning')
        return redirect(url_for('login'))

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    # If the user is not an admin, redirect to the admin page
    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))

    # Access the collection specific to the Business ID provided
    new_collection = db_business[f'{business_id}news']  # Collection for news of the specific business_id

    # Buscar o plano do usuário no MongoDB dentro da coleção específica do business_id
    business_collection = db_business[business_id]  # Coleção do negócio
    business_data = business_collection.find_one({}, {"plantype": 1})  # Buscar apenas o campo 'plan'

    if not business_data or "plantype" not in business_data:
        print("Plan information not found. Please contact support.")
        flash("Plan information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))

    # Verificar o plano do usuário
    plan = get_user_plan(business_id)  # Função que retorna o plano do usuário

    if plan is None:
        print("Invalid plan or not found.")
        flash("Invalid plan or not found.", 'danger')
        return redirect(url_for('index'))

    user_plan = business_data["plantype"]
    plans_collection = db_business["plans"]
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_news": 1})
    
    if not plan_data or "limit_news" not in plan_data:
        print("Plan limit information not found. Please contact support.")
        flash("Plan limit information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))
    
    limit_news = plan_data["limit_news"]
    current_news_count = new_collection.count_documents({"type": "news"})
    
    if current_news_count >= limit_news:
        print("You have reached the maximum number of news entries for your plan.")
        flash("You have reached the maximum number of news entries for your plan.", 'danger')
        return redirect(url_for('admin'))

    if not business_data or "plantype" not in business_data:
        print("Plan information not found. Please contact support.")
        flash("Plan information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))

    user_plan = business_data["plantype"]

    # Buscar os limites do plano na coleção 'plans', que está separada
    plans_collection = db_business["plans"]  # Pegamos a coleção `plans`
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_news": 1})  # Buscar limite
    
    try:
        title = request.form.get('title')
        news = request.form.get('news')

        # Capture form data for the new new entry
        new_data = {
            'title': title,
            'news': news,
            'id_database': 'businessdata',
            'business_id': business_id,
            'added_by': user_name,
            'type': "news",
            'created_at': datetime.now(timezone.utc)
        }

        # Insert the new data into MongoDB
        new_collection.insert_one(new_data)
        print(f"News added successfully!: {new_data['title']}")
        flash("News added successfully!", 'success')
        
        print("News saved successfully!")
        flash("News saved successfully!", 'success')
        return redirect(url_for('admin'))

    except Exception as e:
        print(f"Error processing the document: {str(e)}")
        flash(f"Error processing the document: {str(e)}", 'danger')
        return redirect(url_for('admin'))

@app.route('/view_questions_and_answers/<business_id>/<int:page>', methods=['GET', 'POST'])
@login_required
def view_questions_and_answers(business_id, page):
    # Access the correct database (db_business)
    db_business = client['businessdata']  # Database for businesses

    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("You must be logged in to add a question and answer.")
        flash("You must be logged in to add a question and answer.", 'warning')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))

    try:
        # Set the number of results per page
        results_per_page = 10
        
        # Calculate the number of documents to skip based on the page number
        skip = (page - 1) * results_per_page
        
        # Create the collection name based on the business_id
        collection_name = f'{business_id}info'
        
        # Check if the collection exists in the correct database
        if collection_name not in db_business.list_collection_names():
            return redirect(url_for('index'))
        
        # Access the info collection in the database
        infos = list(db_business[collection_name].find(
            {"type": "answer_question"},  # Filtro para pegar apenas documentos com 'type': 'question_answer'
            {"_id": 1, "question": 1, "answer": 1, "procedure_path": 1}
        ).skip(skip).limit(results_per_page))

        # Count the total number of infos in the collection
        total_question_and_answers = db_business[collection_name].count_documents({})
        total_pages = (total_question_and_answers // results_per_page) + (1 if total_question_and_answers % results_per_page > 0 else 0)
        
        # Pass the necessary variables to the template
        return render_template('view_questions_and_answers.html', user_name=user_name, user_data=user, infos=infos, page=page, total_pages=total_pages, business_id=business_id, is_admin=is_admin, user_business_id=business_id)
                               
    except Exception as e:
        print(f"Error while viewing question: {str(e)}")
        flash(f"Error while viewing question: {str(e)}", 'danger')
        return redirect(url_for('admin'))
    
@app.route('/view_documents/<business_id>/<int:page>', methods=['GET', 'POST'])
@login_required
def view_documents(business_id, page):
    # Access the correct database (db_business)
    db_business = client['businessdata']  # Database for businesses

    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("You must be logged in to add a question and answer.")
        flash("You must be logged in to add a question and answer.", 'warning')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))

    try:
        # Set the number of results per page
        results_per_page = 10
        
        # Calculate the number of documents to skip based on the page number
        skip = (page - 1) * results_per_page
        
        # Create the collection name based on the business_id
        collection_name = f'{business_id}info'
        
        # Check if the collection exists in the correct database
        if collection_name not in db_business.list_collection_names():
            return redirect(url_for('index'))
        
        # Access the info collection in the database
        infos = list(db_business[collection_name].find(
            {"type": "document"},  # Filtro para pegar apenas documentos com 'type': 'document'
            {"_id": 1, "question": 1, "answer": 1}
        ).skip(skip).limit(results_per_page))
        
        # Count the total number of infos in the collection
        total_question_and_answers = db_business[collection_name].count_documents({})
        total_pages = (total_question_and_answers // results_per_page) + (1 if total_question_and_answers % results_per_page > 0 else 0)
        
        # Pass the necessary variables to the template
        return render_template('view_documents.html', user_name=user_name, user_data=user, infos=infos, page=page, total_pages=total_pages, business_id=business_id, is_admin=is_admin, user_business_id=business_id)
                               
    except Exception as e:
        return redirect(url_for('index'))
    
@app.route('/view_news/<business_id>/<int:page>', methods=['GET', 'POST'])
@login_required
def view_news(business_id, page):
    # Access the correct database (db_business)
    db_business = client['businessdata']  # Database for businesses
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("You must be logged in to add a news.")
        flash("You must be logged in to add a news.", 'warning')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    # Check if the user is an admin
    is_admin = check_user_is_admin(business_id, user_name)

    if not is_admin:
        print(f"User {user_name} is not an admin. Action not allowed.")
        flash(f"User {user_name} is not an admin. Action not allowed.", 'danger')
        return redirect(url_for('index'))

    try:
        # Set the number of results per page
        results_per_page = 1
        
        # Calculate the number of news to skip based on the page number
        skip = (page - 1) * results_per_page
        
        # Create the collection name based on the business_id
        collection_name = f'{business_id}news'
        
        # Check if the collection exists in the correct database
        if collection_name not in db_business.list_collection_names():
            print(f"Error: Collection {collection_name} not found: {db_business.list_collection_names()}")
            flash(f"Error: Collection {collection_name} not found: {db_business.list_collection_names()}", 'warning')
            return redirect(url_for('index'))
        
        # Access the new collection in the database
        news = list(db_business[collection_name].find(
            {"type": "news"},  # Filtro para pegar apenas news com 'type': 'news'
            {"_id": 1, "title": 1, "news": 1, "created_at": 1} 
        ).sort([("created_at", -1)]).skip(skip).limit(results_per_page))
        
        # Count the total number of news in the collection
        total_news = db_business[collection_name].count_documents({})
        total_pages = (total_news // results_per_page) + (1 if total_news % results_per_page > 0 else 0)
        
        # Pass the necessary variables to the template
        return render_template('view_news.html', user_name=user_name, user_data=user, page=page, total_pages=total_pages, business_id=business_id, is_admin=is_admin, user_business_id=business_id, news=news)
                               
    except Exception as e:
        print(f"Error while viewing news: {str(e)}")
        flash(f"Error while viewing news: {str(e)}", 'danger')
        return redirect(url_for('index'))

# Route to edit info
@app.route('/edit_questions_and_answers/<business_id>/<info_id>', methods=['GET', 'POST'])
@login_required
def edit_questions_and_answers(business_id, info_id):
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("You need to be logged in to edit the question and answer.")
        flash("You need to be logged in to edit the question and answer.", 'error')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})
    
    collection_name = f"{business_id}info"  # Define the collection name based on business_id

    if request.method == 'POST':
        action = request.form.get('action')

        if action == "back":
            # Redireciona sem salvar
            print("No changes were made. Returning to the question list.")
            flash("No changes were made. Returning to the question list.", 'info')
            return redirect(url_for('view_questions_and_answers', user_name=user_name, user_data=user, business_id=business_id, page=1))

        elif action == "save":
            # Atualiza a info no banco de dados
            updated_question = request.form['question']
            updated_answer = request.form['answer']
            updated_procedure_path = request.form['procedure_path']

            # Check if the fields are empty
            if not updated_question or not updated_answer:
                print("Question and Answer cannot be empty.")
                flash("Question and Answer cannot be empty.", 'error')
                return render_template('edit_questions_and_answers.html', user_name=user_name, user_data=user, business_id=business_id, info=info)

            # Update the info in the database using the provided info_id
            db_business[collection_name].update_one(
                {"_id": ObjectId(info_id)},
                {"$set": {
                    "question": updated_question,
                    "answer": updated_answer,
                    "procedure_path": updated_procedure_path
                }}
            )

            print("Question and answer updated successfully!")
            flash("Question and answer updated successfully!", 'success')
            return redirect(url_for('view_questions_and_answers', user_name=user_name, user_data=user, business_id=business_id, page=1))

    # Fetch the current info data to pre-populate the edit form
    info = db_business[collection_name].find_one({"_id": ObjectId(info_id)})
    if not info:
        print("The question and answer you are trying to edit was not found.")
        flash("The question and answer you are trying to edit was not found.", 'error')
        return redirect(url_for('view_questions_and_answers', user_name=user_name, user_data=user, business_id=business_id, page=1))

    return render_template('edit_questions_and_answers.html', user_name=user_name, user_data=user, business_id=business_id, info=info)

# Route to edit info
@app.route('/edit_documents/<business_id>/<info_id>', methods=['GET', 'POST'])
@login_required
def edit_documents(business_id, info_id):
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("You need to be logged in to edit the document.")
        flash("You need to be logged in to edit the document.", 'error')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})
    
    collection_name = f"{business_id}info"  # Define the collection name based on business_id

    if request.method == 'POST':
        action = request.form.get('action')

        if action == "back":
            print("No changes were made. Returning to the question list.")
            flash("No changes were made. Returning to the question list.", 'info')
            return redirect(url_for('view_documents', user_name=user_name, user_data=user, business_id=business_id, page=1))

        elif action == "save":
            # Atualiza a info no banco de dados
            updated_question = request.form['question']
            updated_answer = request.form['answer']
            # updated_procedure_path = request.form['procedure_path']

            # Check if the fields are empty
            if not updated_question or not updated_answer:
                print("Document cannot be empty.")
                flash("Document cannot be empty.", 'error')
                return render_template('edit_documents.html', user_name=user_name, user_data=user, business_id=business_id, info=info)

            # Update the info in the database using the provided info_id
            db_business[collection_name].update_one(
                {"_id": ObjectId(info_id)},
                {"$set": {
                    "question": updated_question,
                    "answer": updated_answer
                }}
            )

            print("Document updated successfully!")
            flash("Document updated successfully!", 'success')
            return redirect(url_for('view_documents', user_name=user_name, user_data=user, business_id=business_id, page=1))

    # Fetch the current info data to pre-populate the edit form
    info = db_business[collection_name].find_one({"_id": ObjectId(info_id)})
    if not info:
        print("The document you are trying to edit was not found.")
        flash("The document you are trying to edit was not found.", 'error')
        return redirect(url_for('view_documents', user_name=user_name, user_data=user, business_id=business_id, page=1))

    return render_template('edit_documents.html', user_name=user_name, user_data=user, business_id=business_id, info=info)

@app.route('/edit_news/<business_id>/<new_id>', methods=['GET', 'POST'])
@login_required
def edit_news(business_id, new_id):
    # Get the username and business_id from the session
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Check if the user is logged in
    if not user_name or not business_id:
        print("You need to be logged in to edit the news.")
        flash("You need to be logged in to edit the news.", 'error')
        return redirect(url_for('login'))
    
    # Fetch the user's data from the business collection
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})
    
    collection_name = f"{business_id}news"  # Define the collection name based on business_id

    if request.method == 'POST':
        action = request.form.get('action')

        # Handle the "back" action without saving
        if action == "back":
            print("No changes were made. Returning to the question list.")
            flash("No changes were made. Returning to the question list.", 'info')
            return redirect(url_for('view_news', user_name=user_name, user_data=user, business_id=business_id, page=1))

        # Handle the "save" action to update the news
        elif action == "save":
            updated_question = request.form.get('title')
            updated_answer = request.form.get('news')

            # Check if the fields are empty
            if not updated_question or not updated_answer:
                print("News cannot be empty.")
                flash("News cannot be empty.", 'error')
                return render_template('edit_news.html', user_name=user_name, user_data=user, business_id=business_id, new=new)

            # Update the new in the database using the provided new_id
            db_business[collection_name].update_one(
                {"_id": ObjectId(new_id)},
                {"$set": {
                    "title": updated_question,
                    "news": updated_answer
                }}
            )

            print("News updated successfully!")
            flash("News updated successfully!", 'success')
            return redirect(url_for('view_news', user_name=user_name, user_data=user, business_id=business_id, page=1))

    # Fetch the current new data to pre-populate the edit form
    new = db_business[collection_name].find_one({"_id": ObjectId(new_id)})

    if not new:
        print("The news you are trying to edit was not found.")
        flash("The news you are trying to edit was not found.", 'error')
        return redirect(url_for('view_news', user_name=user_name, user_data=user, business_id=business_id, page=1))

    return render_template('edit_news.html', user_name=user_name, user_data=user, business_id=business_id, new=new)

# Route to delete info
@app.route('/delete_questions_and_answers/<business_id>/<info_id>', methods=['GET'])
@login_required
def delete_questions_and_answers(business_id, info_id):

    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    collection_name = f"{business_id}info"  # Define the collection name based on business_id

    # Delete the info from the database using the provided info_id
    db_business[collection_name].delete_one({"_id": ObjectId(info_id)})
    print(f"Document deleted succesfully")
    flash(f"Document deleted succesfully", 'info')
    return redirect(url_for('view_questions_and_answers', business_id=business_id, page=1))

# Route to delete info
@app.route('/delete_documents/<business_id>/<info_id>', methods=['GET'])
@login_required
def delete_documents(business_id, info_id):
    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash(f"User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    collection_name = f"{business_id}info"  # Define the collection name based on business_id

    # Delete the info from the database using the provided info_id
    db_business[collection_name].delete_one({"_id": ObjectId(info_id)})
    print(f"Document deleted succesfully")
    flash(f"Document deleted succesfully", 'info')
    return redirect(url_for('view_documents', business_id=business_id, page=1))

# Route to delete new
@app.route('/delete_news/<business_id>/<new_id>', methods=['GET'])
@login_required
def delete_news(business_id, new_id):

    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash(f"User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    collection_name = f"{business_id}news"  # Define the collection name based on business_id

    # Delete the new from the database using the provided new_id
    db_business[collection_name].delete_one({"_id": ObjectId(new_id)})
    print(f"News deleted succesfully")
    flash(f"News deleted succesfully", 'info')
    return redirect(url_for('view_news', business_id=business_id, page=1))
    
# Route for chatbot page
@app.route('/chatbot')
@login_required
def chatbot():
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    return render_template('chatbot.html', user_name=user_name, user_data=user, business_id=business_id)

@app.route('/ask', methods=['POST'])
@login_required
def ask():
    """
    Route to ask the chatbot a question. Validates user authentication, 
    checks the chatbot usage limit, updates the admin's chatbot usage counter, 
    and returns the chatbot's response.
    """
    # Validate user authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Connect to relevant collections
    business_collection = db_business[business_id]
    plans_collection = db_business["plans"]
    
    # Retrieve user's plan type
    business_data = business_collection.find_one({}, {"plantype": 1})
    user_plan = business_data.get("plantype")
    
    # Retrieve chatbot usage limit from the plans collection
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_chatbot": 1})
    if not plan_data or "limit_chatbot" not in plan_data:
        print("Plan limit information not found. Please contact support.")
        flash("Plan limit information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))
    
    limit_chatbot = plan_data["limit_chatbot"]
    admin_chatbot_usage = business_collection.find_one({"role": "admin"}, {"chatbot_usage": 1}) # Retrieve the admin's chatbot usage count
    current_chatbot_count = admin_chatbot_usage.get("chatbot_usage", 0) if admin_chatbot_usage else 0
    
    # Check if chatbot usage exceeds the plan limit
    if current_chatbot_count >= limit_chatbot:
        return jsonify({'answer': 'You have reached the maximum number of chat entries for your plan.'})
    
    # Retrieve the question from the request
    data = request.json
    question = data.get('question', '')
    
    # Ensure a valid question is provided
    if not question:
        return jsonify({'error': 'Invalid question'}), 400
    
    # Call the chatbot function to generate a response
    response = ask_question(question, business_id)
    
    # Handle errors in the chatbot response
    if 'error' in response:
        return jsonify({'error': response['error']}), 500
    
    # Increment the chatbot usage counter for the admin
    business_collection.update_one(
        {"role": "admin"}, 
        {"$inc": {"chatbot_usage": 1}}
    )
    
    # Return the chatbot's answer
    return jsonify({'answer': response['answer']})

@app.route('/ask_data', methods=['POST'])
@login_required
def ask_data():
    """
    Route to ask the chatbot a question. Validates user authentication, 
    checks the chatbot usage limit, updates the admin's chatbot usage counter, 
    and returns the chatbot's response.
    """ 
    # Validate user authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Connect to relevant collections
    business_collection = db_business[business_id]
    plans_collection = db_business["plans"]
    
    # Retrieve user's plan type
    business_data = business_collection.find_one({}, {"plantype": 1})
    user_plan = business_data.get("plantype")
    
    # Retrieve chatbot usage limit from the plans collection
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_chatbot": 1})
    if not plan_data or "limit_chatbot" not in plan_data:
        print("Plan limit information not found. Please contact support.")
        flash("Plan limit information not found. Please contact support.", 'danger')
        return redirect(url_for('admin'))
    
    limit_chatbot = plan_data["limit_chatbot"]
    admin_chatbot_usage = business_collection.find_one({"role": "admin"}, {"chatbot_usage": 1}) # Retrieve the admin's chatbot usage count
    current_chatbot_count = admin_chatbot_usage.get("chatbot_usage", 0) if admin_chatbot_usage else 0
    
    # Check if chatbot usage exceeds the plan limit
    if current_chatbot_count >= limit_chatbot:
        return jsonify({'answer': 'You have reached the maximum number of chat entries for your plan.'})
    
    # Retrieve the question from the request
    data = request.json
    question = data.get('question', '')
    
    # Ensure a valid question is provided
    if not question:
        return jsonify({'error': 'Invalid question'}), 400
    
    response = ask_question_data(question, business_id) # Call the chatbot function to generate a response
    
    # Handle errors in the chatbot response
    if 'error' in response:
        return jsonify({'error': response['error']}), 500
    
    # Increment the chatbot usage counter for the admin
    business_collection.update_one(
        {"role": "admin"}, 
        {"$inc": {"chatbot_usage": 1}}
    )
    
    # Return the chatbot's answer
    return jsonify({'answer': response['answer']})

@app.route('/data_analysis', methods=['GET', 'POST'])
@login_required
def data_analysis():
    # Validate user authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    csv_collection_name = f"{business_id}dacsv"
    csv_collection = db_business[csv_collection_name]

    csv_history = list(
        csv_collection.find(
            {},
            {"_id": 1, "file_name": 1, "user_input": 1, "created_at": 1}
        ).sort("created_at", -1).limit(10)
    )

    if request.method == 'POST':
        # === Register route access in MongoDB ===
        try:
            # Define which file or URL was used (if applicable — update logic if needed)
            file_or_url = request.args.get('source') or 'Manual Upload'
            
            collection_name = f"{business_id}notebook"
            db_business[collection_name].insert_one(
                {
                "dataanalysis": "Data Analyisis AI",
                "username": user_name,
                "business_id": business_id,
                "file_name": file_or_url,
                "file_lines": "Not Availablbe",
                "file_columns": "Not Availablbe",
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        except Exception as e:
            print(f"Could not save access log to MongoDB: {e}")
            flash("Could not save access log to Database.", 'danger')

    # Apenas renderiza a página onde o usuário pode carregar o arquivo CSV
    return render_template('data_analysis.html', business_id=business_id, user_name=user_name, user_data=user, csv_history=csv_history)

@app.route('/data_analysis_googlesheets', methods=['GET', 'POST'])
@login_required
def data_analysis_googlesheets():
    # Validate user authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    gsheet_collection_name = f"{business_id}dags"
    gsheet_collection = db_business[gsheet_collection_name]

    gsheet_history = list(
        gsheet_collection.find(
            {},
            {"_id": 1, "file_name": 1, "url": 1, "user_input": 1, "created_at": 1}
        ).sort("created_at", -1).limit(10)
    )

    if request.method == 'POST':
        sheet_url = request.form.get('sheet-url')

        if not sheet_url:
            print("Please provide a Google Sheets URL.")
            flash("Please provide a Google Sheets URL.", "danger")
            return render_template("data_analysis_googlesheets.html", user_name=user_name, user_data=user, analysis=None)

        try:
            df, sheet_info = load_google_sheet_data_analysis(sheet_url, business_id)
            analysis = analyze_data_googlesheets(df)
            analysis["info"]["url"] = sheet_url
            df_html = df.to_html(classes="dataframe", index=False)

            collection_name = f"{business_id}notebook"
            db_business[collection_name].insert_one(
                    {
                    "dataanalysis": "Data Analyisis AI",
                    "username": user_name,
                    "business_id": business_id,
                    "file_name": sheet_url,
                    "file_lines": "Not Availablbe",
                    "file_columns": "Not Availablbe",
                    "accessed_at": datetime.now(timezone.utc)
                    }
                )

            return render_template("data_analysis_googlesheets.html", analysis=analysis, df_html=df_html, sheet_info=sheet_info)
        
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return render_template("data_analysis_googlesheets.html", user_name=user_name, user_data=user, analysis=None)

    return render_template("data_analysis_googlesheets.html", business_id=business_id, user_name=user_name, user_data=user, gsheet_history=gsheet_history, analysis=None)

@app.route('/data_analysis_result', methods=['POST'])
@login_required
def data_analysis_result():
    # Validate user authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Connect to relevant collections
    business_collection = db_business[business_id]
    plans_collection = db_business["plans"]
    
    # Retrieve user's plan type
    business_data = business_collection.find_one({}, {"plantype": 1})
    user_plan = business_data.get("plantype")

    csv_collection_name = f"{business_id}csv"
    csv_collection = db_business[csv_collection_name]
    
    # Retrieve chatbot usage limit from the plans collection
    plan_data = plans_collection.find_one({"plan": user_plan}, {"limit_data_analisys": 1})
    if not plan_data or "limit_data_analisys" not in plan_data:
        print("Plan limit information not found. Please contact support.")
        flash("Plan limit information not found. Please contact support.", 'danger')
        return redirect(url_for('index'))
    
    limit_data_analisys = plan_data["limit_data_analisys"]
    admin_data_analisys_usage = business_collection.find_one({"role": "admin"}, {"data_analisys_usage": 1}) # Retrieve the admin's data_analysis usage count
    current_data_analysis_count = admin_data_analisys_usage.get("data_analisys_usage", 0) if admin_data_analisys_usage else 0
    
    # Check if chatbot usage exceeds the plan limit
    if current_data_analysis_count >= limit_data_analisys:
        print("You have reached the maximum number of data analisys entries for your plan.")
        flash("You have reached the maximum number of data analisys entries for your plan.", 'warning')
        return redirect(url_for('index'))
    
    try:
        history_id = request.form.get("history_id")
        source_page = request.form.get("source_page")

        df = None
        source_type = None
        file_name = None
        file_lines = None
        file_columns = None

        # ------------------------------
        # Case 1: CSV
        if source_page == "data_analysis" and history_id:
            hist_collection = db_business[f"{business_id}dacsv"]

            try:
                obj_id = ObjectId(history_id)

            except Exception:
                print("Invalid History ID format.")
                flash("Invalid History ID format.", "danger")
                return redirect(url_for("data_analysis"))
            
            data_analysis_doc = hist_collection.find_one({"_id": obj_id})

            if not data_analysis_doc:
                print("No historical data found.")
                flash("Historical data not found.", "warning")
                return redirect(url_for("data_analysis"))

            csv_collection = db_business[f"{business_id}csv"]
            csv_collection.delete_many({}) # Clear previous analysis data for this business_id

            analysis_doc = {
                "business_id": business_id,
                "charts": data_analysis_doc.get("charts", []),
                "explanations": data_analysis_doc.get("explanations", []),
                "explanationsai": data_analysis_doc.get("explanationsai", []),
                "summary": data_analysis_doc.get("summary", ""),
                "created_at": datetime.now(timezone.utc)
            }
            csv_collection.insert_one(analysis_doc)

        # ------------------------------
        # Case 2: Google Sheets
        elif source_page == "data_analysis_googlesheets" and history_id:
            hist_collection = db_business[f"{business_id}dags"]

            try:
                obj_id = ObjectId(history_id)

            except Exception:
                print("Invalid History ID format.")
                flash("Invalid History ID format.", "danger")
                return redirect(url_for("data_analysis_googlesheets"))

            data_analysis_doc = hist_collection.find_one({"_id": obj_id})

            if not data_analysis_doc:
                print("No historical data found.")
                flash("Historical data not found.", "warning")
                return redirect(url_for("data_analysis_googlesheets"))

            csv_collection = db_business[f"{business_id}csv"]
            csv_collection.delete_many({}) # Clear previous analysis data for this business_id
            
            analysis_doc = {
                "business_id": business_id,
                "charts": data_analysis_doc.get("charts", []),
                "explanations": data_analysis_doc.get("explanations", []),
                "explanationsai": data_analysis_doc.get("explanationsai", []),
                "summary": data_analysis_doc.get("summary", ""),
                "created_at": datetime.now(timezone.utc)
            }
            csv_collection.insert_one(analysis_doc)

        # ------------------------------
        # Case 3: New upload (CSV or Google Sheets)
        else:
            # Increment the chatbot usage counter for the admin
            business_collection.update_one(
                {"role": "admin"}, 
                {"$inc": {"data_analisys_usage": 1}}
            )

            # Case 3.1: upload CSV file
            if 'fileInput' in request.files:
                file = request.files['fileInput']
                if file.filename == '' or not file.filename.endswith('.csv'):
                    print("Invalid CSV file.")
                    flash("Invalid CSV file.", 'warning')
                    return redirect(url_for('data_analysis'))
                
                df = pd.read_csv(file, encoding='utf-8', on_bad_lines='skip')
                source_type = "csv"
                file_name = file.filename
                file_lines, file_columns = df.shape

            # Case 3.2: Google Sheets data (for example, the spreadsheet URL comes from a field)
            elif 'sheet-url' in request.form:
                sheet_url = request.form.get('sheet-url')
                if not sheet_url:
                    print("Google Sheets URL is required.")
                    flash("Google Sheets URL is required.", 'warning')
                    return redirect(url_for('data_analysis_googlesheets'))
                
                df, sheet_info = load_google_sheet_data_analysis(sheet_url, business_id)
                source_type = "googlesheets"
                file_name = sheet_info.get("sheet_title", sheet_url)
                file_lines, file_columns = df.shape

            # Case 3.3: No data provided for analysis
            else:
                print("No data provided for analysis.")
                flash("No data provided for analysis.", 'warning')
                return redirect(url_for('data_analysis'))
            
            # Ensure df is a DataFrame
            if not isinstance(df, pd.DataFrame):
            
                if isinstance(df, list):
                    df = pd.DataFrame(df)

                elif isinstance(df, dict):
                    df = pd.DataFrame([df])
                    
                else:
                    print(f"Error converting data to DataFrame: {str(e)}")
                    flash(f"Error converting data to DataFrame: {str(e)}", "danger")
                    return redirect(url_for('data_analysis'))
                    
            # Define a user input (or get it from a form if desired)
            user_input = request.form.get('user_input', None)  # It can also come from request.form.get('user_input')

            if not user_input:
                print("User input not provided.")
                flash("EUser input not provided.", 'warning')
                return redirect(url_for('data_analysis'))
            
            # Guarantee df is a DataFrame (force conversion if needed)
            if not isinstance(df, pd.DataFrame):

                if isinstance(df, list):
                    df = pd.DataFrame(df)
                    
                elif isinstance(df, dict):
                    df = pd.DataFrame([df])

                else:
                    print(f"Error converting data to DataFrame: {type(df)}")
                    flash("Error converting data to DataFrame. Please upload a valid CSV or Google Sheet.", "danger")
                    return redirect(url_for('data_analysis'))

            analyze_data(df, user_input) # Call the analysis function
            data_analysis_doc = csv_collection.find_one({"business_id": business_id}) # Fetch the document with the analysis data for this business_id

            # Fetch the newly saved data for rendering
            data_analysis_doc = csv_collection.find_one({
                "business_id": business_id,
                "charts": {"$exists": True, "$ne": []},
                "summary": {"$exists": True},
                "explanations": {"$exists": True},
                "explanationsai": {"$exists": True}
            })

            if not data_analysis_doc:
                print("Error retrieving results after analysis.")
                flash("Error retrieving results after analysis.", 'warning')
                return redirect(url_for('data_analysis'))
            
            # Save entry + result to historical collection
            if source_type == "csv":
                hist_collection_name = f"{business_id}dacsv"

            else:
                hist_collection_name = f"{business_id}dags"

            hist_collection = db_business[hist_collection_name]

            # Keep only last 5 entries
            total_docs = hist_collection.count_documents({})
            if total_docs >= 5:
                oldest_doc = hist_collection.find().sort("created_at", 1).limit(1)
                if oldest_doc:
                    hist_collection.delete_one({"_id": oldest_doc[0]["_id"]})

            hist_collection.insert_one({
                "business_id": business_id,
                "username": user_name,
                "source_type": source_type,
                "file_name": file_name,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "user_input": user_input,
                "file": data_analysis_doc.get("file", ""),
                "charts": data_analysis_doc.get("charts", []),
                "explanations": data_analysis_doc.get("explanations", []),
                "explanationsai": data_analysis_doc.get("explanationsai", []),
                "summary": data_analysis_doc.get("summary", ""),
                "created_at": datetime.now(timezone.utc)
            })

            business_collection.update_one({"role": "admin"}, {"$inc": {"data_analysis_usage": 1}})

        business_collection = db_business[business_id]
        user = business_collection.find_one({"username": user_name})

        return render_template(
            'data_analysis_result.html',
            charts=data_analysis_doc.get("charts", []),
            explanations=data_analysis_doc.get("explanations", []),
            explanationsai=data_analysis_doc.get("explanationsai", []),
            summary=data_analysis_doc.get("summary", ""),
            business_id=business_id,
            user_name=user_name,
            user_data=user
        )

    except Exception as e:
        print(f"Error processing the file. Please check if the CSV is correct: {str(e)}")  # Tratar exceção, caso ocorra
        flash("Error processing the file. Please check if the CSV is correct.", 'danger')
        traceback.print_exc()
        return redirect(url_for('data_analysis'))

# Download route
@app.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf():
    # Retrieve the analysis data stored in the session
    result = session.get('data_analysis_result')

    if not result:
        return "Error: Results not found.", 400

    
    buffer = BytesIO() # Create a buffer to generate the PDF
    c = canvas.Canvas(buffer, pagesize=letter) # Create a canvas for the PDF with letter page size
    width, height = letter
    y_position = height - 40 # Set the initial position for the content
    line_height = 12
    c.setFont("Helvetica-Bold", 14) # Add title to the PDF
    c.drawString(40, y_position, "Data Analysis Result")
    y_position -= line_height * 2
    c.setFont("Helvetica", 10) # Add summary
    c.drawString(40, y_position, "Analysis Summary:")
    y_position -= line_height

    summary = result['summary']
    for line in summary.split("\n"):
        c.drawString(40, y_position, line)
        y_position -= line_height

    # Add charts and explanations
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y_position, "Charts and Explanations:")
    y_position -= line_height * 2

    # Add the charts in SVG (base64) format and explanations
    for chart, explanation, explanationai in zip(result['charts'], result['explanations'], result['explanationsai']):
        # Here you can create a method to convert the SVG chart into an image and add it to the PDF
        # As an example, we are only including the explanation
        c.setFont("Helvetica", 10)
        c.drawString(40, y_position, explanation)
        y_position -= line_height

        c.setFont("Helvetica", 10)
        c.drawString(40, y_position, explanationai)
        y_position -= line_height

        if y_position < 40:
            c.showPage()  # Create a new page if the content exceeds the page limit

    c.save() # Save the PDF to the buffer
    buffer.seek(0) # Return to the beginning of the buffer

    # Send the PDF file for download
    return send_file(buffer, as_attachment=True, download_name="data_analysis_result.pdf", mimetype='application/pdf')

@app.route('/payment/<plan>', methods=['GET'])
def payment(plan):
    """
    Render the payment page for the selected subscription plan.

    This route validates the selected plan, checks user authentication and business context, 
    and then renders the payment page. It also verifies that the business collection exists 
    in the MongoDB database.

    Args:
        plan (str): The name of the subscription plan. Must be either 'standard' or 'professional'.

    Returns:
        Response:
            - Redirect to the login page if the user is not authenticated or the plan is invalid.
            - Rendered 'payment.html' template if everything is valid.
            - Rendered error message if the business collection is not found.

    Side Effects:
        - Displays flash messages to inform the user about errors or authentication issues.
        - Logs relevant information and errors to the console.

    Raises:
        Exception: If an error occurs while accessing the MongoDB database.

    Notes:
        - This route is intended to be accessed before initiating the payment process.
        - It ensures the system is ready to collect payment information for the user’s business.
    """
    if plan not in ['standard', 'professional']:
        return redirect(url_for('login'))

    # Check if the user is authenticated and is an admin
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    if not business_id:
        print("Error: Business ID not found! Please log in again.")
        flash("Error: Business ID not found! Please log in again.", 'error')
        return redirect(url_for('login'))  # Ou qualquer outra página adequada
    
    try:
        # Verifica se a coleção do business_id existe no MongoDB
        business_collection = db_business[business_id]

        if business_collection is None:
            return render_template('payment.html', error=f'Business collection {business_id} not found in the database!')
        
    except Exception as e:
        print("Error accessing database for Business ID {business_id}")
        flash("Error accessing database for Business ID {business_id}", 'error')
        return redirect(url_for('login'))

    return render_template('payment.html', business_id=business_id, plan=plan)

@app.route('/payment_processing/<plan>', methods=['POST'])
def payment_processing(plan):
    """
    Process the payment for a selected plan and update the user's subscription details.

    This endpoint handles the Stripe payment process for a given plan (standard or professional).
    It validates the user session, fetches plan details, confirms the payment via Stripe, 
    and updates both the subscription data and the payment log in MongoDB.

    Args:
        plan (str): The selected plan name (must be 'standard' or 'professional').

    Returns:
        Response: Redirects to:
            - 'login' page if the user is not authenticated.
            - 'payment' page if plan is invalid or payment fails.
            - 'index' page if payment is successful.

    Form Parameters:
        - payment_method_id (str): Stripe payment method ID.
        - email (str): User's email.
        - country (str): User's country.
        - phone (str): User's phone number.
        - card_name (str): Name on the card.
        - cpf_cnpj (str): CPF or CNPJ of the user.
        - payment_option (str): Payment mode ('installments' or immediate).

    Raises:
        stripe.error.StripeError: On Stripe API failure or invalid payment.
    
    Side Effects:
        - Creates a Stripe PaymentIntent.
        - Updates the `plantype`, `validity_date`, and `payment_info` in the user's collection.
        - Inserts a payment record in the `payments` collection in MongoDB.
        - Displays flash messages depending on success/failure.
    """
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("User not authenticated.")
        flash("User not authenticated.", 'error')
        return redirect(url_for('login'))

    if plan not in ['standard', 'professional']:
        print("Invalid plan!")
        flash("Invalid plan!", 'error')
        return redirect(url_for('payment', plan=plan))

    payment_method_id = request.form['payment_method_id']
    email = request.form['email']
    country = request.form['country']
    phone = request.form['phone']
    card_name = request.form['card_name']
    cpf_cnpj = request.form['cpf_cnpj']
    payment_option = request.form['payment_option']


    try:
        plans_collection = db_business["plans"] # Access the plans collection
        plan_data = plans_collection.find_one({"plan": plan}) # Fetch the data of the selected plan

        if not plan_data:
            print("Plan not found!")
            flash("Plan not found!", 'error')
            return redirect(url_for('payment', plan=plan))
        
        price_dollars = plan_data["price"] # Get the plan price in dollars

        if price_dollars <= 0: # Check if the price is valid
            print("Invalid price for the plan.")
            flash("Invalid price for the plan.", 'error')
            return redirect(url_for('payment', plan=plan))
        
        amount_in_cents = int(price_dollars * 100) # Convert the price from dollars to cents (Stripe requires amount in cents)

        # Create the charge in Stripe
        # Determine payment options according to user's choice
        if payment_option == 'installments':
            # Check if installments are supported
            payment_intent = stripe.PaymentIntent.create(
                amount=amount_in_cents,
                currency='usd',
                payment_method=payment_method_id,
                confirm=True,
                payment_method_options={
                    'card': {
                        'installments': {
                            'enabled': True,
                            'plan': {
                                'count': 12, # Number of installments
                                'interval': 'month', # Interval between installments
                                'type': 'fixed_count' # Fixed number of installments
                            }
                        }
                    }
                },
                return_url='https://suaurl.com/return',
            )

        else:
            payment_intent = stripe.PaymentIntent.create(
                amount=amount_in_cents, # Amount in cents, adjust as needed
                currency='usd',
                payment_method=payment_method_id,
                confirm=True, # Confirm the payment immediately
                automatic_payment_methods={
                    'enabled': True, # Enable automatic payment methods
                    'allow_redirects': 'never' # Prevent redirects if necessary
                },
                return_url='https://suaurl.com/return', # Return URL after payment
            )

        if payment_intent.status == 'succeeded':
            transaction_id = payment_intent.id
            amount = payment_intent.amount
            currency = payment_intent.currency
            status = payment_intent.status
            payment_date = datetime.now(timezone.utc)
            business_collection = db_business[business_id] # Access the correct collection inside the business database
            validity_date = payment_date + timedelta(days=365) # Calculate validity date (1 year after payment date)

            # Update the user's plan and payment info in the database
            result = business_collection.update_many(
                {},  # Update all documents inside this collection
                {
                    "$set": {
                        "plantype": plan, # Update the plan to the selected one
                        "validity_date": validity_date,
                        "payment_info": {
                            "transaction_id": transaction_id, # Stripe transaction ID
                            "amount": amount / 100, # Paid amount, converted to dollars
                            "currency": currency,
                            "status": status,
                            "payment_date": payment_date,
                            "payment_method_id": payment_method_id,
                            "payment_option": payment_option
                        }
                    }
                }
            )

            # Insert payment data in the 'payments' collection
            payments_collection = db_business["payments"]

            payment_data = {
                "transaction_id": transaction_id,
                "amount": amount / 100,
                "currency": currency,
                "status": status,
                "payment_date": payment_date,
                "user_email": email,
                "user_country": country,
                "user_phone": phone,
                "card_name": card_name,
                "cpf_cnpj": cpf_cnpj,
                "payment_method_id": payment_method_id,
                "payment_option": payment_option,
                "validity_date": validity_date
            }

            payments_collection.insert_one(payment_data)

            if result.matched_count == 0:
                print("User not found.")
                flash("User not found.", 'error')
            else:
                print(f"Plan {plan} successfully updated!")
                flash(f"Plan {plan} successfully updated!", 'success')

            print(f"Payment successfully confirmed! The {plan} plan has been activated.")
            flash(f"Payment successfully confirmed! The {plan} plan has been activated.", 'success')
            return redirect(url_for('index', plan=plan))
        
        else:
            print("Error processing payment!")
            flash("Error processing payment!", 'error')
            return redirect(url_for('payment', plan=plan))

    except stripe.error.StripeError as e:
        print(f"Payment error: {str(e)}")
        flash(f"Payment error: {str(e)}", 'error')
        return redirect(url_for('payment', plan=plan))

@app.route('/get_stripe_public_key')
def get_stripe_public_key():
    """
    Return the Stripe public key used for client-side Stripe.js initialization.

    Returns:
        Response: JSON object with the Stripe publishable key.

        Example:
            {
                "stripe_public_key": "pk_test_XXXXXXXXXXXXXXXXXXXX"
            }

    Notes:
        - The public key is read from the environment variable STRIPE_PUB_KEY.
        - This route is typically used by the frontend to configure Stripe.
    """
    return jsonify({'stripe_public_key': os.getenv('STRIPE_PUB_KEY')})

@app.route('/help')
def help():
    """
    Render the help/tutorial page with video guides and content from the help database.

    This route retrieves help video filenames stored in GridFS and matches them with their
    corresponding content from the MongoDB 'helpaiiqdata' collection. It renders a help page
    where users can view embedded tutorial videos.

    Returns:
        Response: Rendered HTML template 'help.html' with context variables:
            - video_tutorial1 (str | None): Filename for the "Register" tutorial.
            - video_tutorial2 (str | None): Filename for the "Add/Delete User" tutorial.
            - video_tutorial3 (str | None): Filename for the "Talking with Data Analysis" tutorial.
            - video1 (dict | None): MongoDB document for video 1 metadata.
            - video2 (dict | None): MongoDB document for video 2 metadata.
            - video3 (dict | None): MongoDB document for video 3 metadata.

    Notes:
        - Uses GridFS to retrieve video files by name.
        - Uses MongoDB collection 'helpaiiqdata' to load video descriptions or metadata.
        - Videos and metadata are dynamically injected into the rendered template.
    """
    video1_file = fshelp.find_one({'filename': 'Register.mp4'})
    video2_file = fshelp.find_one({'filename': 'Add_and_Delete_User.mp4'})
    video3_file = fshelp.find_one({'filename': 'Talking_with_data_analysis.mp4'})

    video_tutorial1 = video1_file.filename if video1_file else None
    video_tutorial2 = video2_file.filename if video2_file else None
    video_tutorial3 = video3_file.filename if video3_file else None

    user_collection_help = db_help['helpaiiqdata']

    video1 = user_collection_help.find_one({"page": "help", "field": "video1"})
    video2 = user_collection_help.find_one({"page": "help", "field": "video2"})
    video3 = user_collection_help.find_one({"page": "help", "field": "video3"})

    return render_template('help.html', video_tutorial1=video_tutorial1, video_tutorial2=video_tutorial2, video_tutorial3=video_tutorial3, video1=video1, video2=video2, video3=video3)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    Log out the user by clearing the session and optionally verifying reCAPTCHA.

    GET:
        Renders the login page with the reCAPTCHA site key.

    POST:
        Clears the current session, performs reCAPTCHA validation, and returns the login page.

    Returns:
        Response: Rendered login HTML page.

    Request Parameters (POST):
        - business_id (str): The business ID from the login form.
        - username (str): The username or email provided for login.
        - password (str): The user's password.
        - g-recaptcha-response (str): Token from Google reCAPTCHA for human verification.

    Notes:
        - The session is cleared on POST to ensure any previous session is invalidated.
        - reCAPTCHA validation is performed using Google's verification API.
        - A flash message is shown if reCAPTCHA verification fails.
    """
    # Clear session data to log the user out
    if request.method == 'GET':
        return render_template('login.html', site_key=site_key)
    
    session.clear()  # Clear the session before starting a new one

    business_id = request.form.get('business_id')
    username_or_email = request.form.get('username')
    password = request.form.get('password')

    recaptcha_response = request.form.get('g-recaptcha-response')
    
    verify_url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post(verify_url, data=payload)
    result = response.json()
    
    if not result.get('success'):
        print("Human verification failed. Please try again.")
        flash("Human verification failed. Please try again.", 'warning')
        return render_template('login.html', site_key=site_key)
    
    return render_template('login.html', site_key=site_key)

@app.route('/video/<source>/<filename>')
def stream_video(source, filename):
    """
    Stream a video file stored in MongoDB GridFS by chunking it to the client.

    Args:
        source (str): The source category of the video ('home' or 'help').
        filename (str): The filename of the video to stream.

    Returns:
        Response: A Flask streaming response with MIME type "video/mp4".
        If the file is not found, returns 404 with a message.
        If an invalid source is provided, returns 400 with an error.

    Raises:
        500 Internal Server Error: If an unexpected exception occurs during file streaming.

    Notes:
        - Videos are retrieved from a GridFS collection depending on the `source` value.
        - The video is streamed in chunks of 4096 bytes.
    """
    try:
        if source == 'home':
            fs = fshome
        elif source == 'help':
            fs = fshelp
        else:
            return "Invalid source", 400

        grid_out = fs.find_one({'filename': filename})
        if not grid_out:
            return "Video not found", 404

        def generate():
            chunk_size = 4096
            while True:
                chunk = grid_out.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        return Response(generate(), mimetype="video/mp4")
    except Exception as e:
        return str(e), 500
    
@app.route('/histogramwithkde', methods=['GET', 'POST'])
@login_required
def histogramwithkde():
    """
    Generate and return histograms with KDE (Kernel Density Estimation) for numeric columns.

    This endpoint allows users to upload a CSV file or provide a Google Sheets URL.
    It extracts numeric columns and generates individual histograms with KDE using seaborn,
    one for each numeric column. The output image is encoded in base64 and returned in JSON.

    Authentication:
        Requires a valid user session with `username` and `business_id`.

    Methods:
        GET, POST

    Request (POST):
        - Upload field: "file" (CSV file)
        - OR form field: "sheet-url-histogramwithkde" (Google Sheets URL)

    Returns:
        dict: JSON object containing:
            - "image" (str): Base64-encoded PNG of the histograms with KDE.

    Raises:
        400 Bad Request: If no file or URL is provided.
        500 Internal Server Error: If data processing or plotting fails.

    Side Effects:
        - Logs metadata in MongoDB `{business_id}notebook` collection:
            - Analysis type: "Histogram with KDE"
            - Username and business ID
            - File name or URL
            - Number of rows and columns
            - UTC timestamp of the operation

    Notes:
        - Uses `sns.histplot(..., kde=True)` for rendering histograms with KDE.
        - Multiple histograms are stacked vertically in one image.
    """
    # Retrieve user session data
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Ensure the user is authenticated
    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure a business ID is present in session
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Access the business-specific MongoDB collection
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-histogramwithkde')
        elif 'sheet-url-histogramwithkde' in request.form and request.form['sheet-url-histogramwithkde'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_histogramwithkde = request.form['sheet-url-histogramwithkde'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_histogramwithkde)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        # Generate the histogram with KDE using seaborn
        numeric_cols = df.select_dtypes(include='number').columns

        if len(numeric_cols) == 0:
            print("There is not numeric columns in yhe file")
            flash("There is not numeric columns in yhe file", "warning")
            return redirect(url_for('index'))
        
        fig, axs = plt.subplots(len(numeric_cols), 1, figsize=(12, 6 * len(numeric_cols)))

        if len(numeric_cols) == 1:
            axs = [axs]

        for ax, col in zip(axs, numeric_cols):
            sns.histplot(df[col].dropna(), kde=True, ax=ax)
            ax.set_title(f'Histogram with KDE - {col}', fontsize=14)
            ax.set_xlabel(col)
            ax.set_ylabel('Frequência')

        plt.tight_layout()

        # Save the plot image to an in-memory buffer
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()

        # Encode the image as a base64 string
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Histogram with KDE",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_histogramwithkde,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        # Return the base64-encoded image in JSON format
        return {"image": img_base64}

    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/boxplot', methods=['GET', 'POST'])
@login_required
def boxplot():
    """
    Generate and return a box plot for all numeric columns in the dataset.

    This endpoint accepts a CSV file or Google Sheets URL, extracts numeric columns,
    and creates a box plot to display their statistical distribution and outliers.
    The resulting chart is encoded in base64 and returned in a JSON response.

    Authentication:
        Requires a valid user session with `username` and `business_id`.

    Methods:
        GET, POST

    Request (POST):
        - Upload field: "file" (CSV file)
        - OR form field: "sheet-url-boxplot" (Google Sheets URL)

    Returns:
        dict: JSON object containing:
            - "image" (str): Base64-encoded PNG of the generated box plot.

    Raises:
        400 Bad Request: If no valid file or URL is provided.
        500 Internal Server Error: If data reading or plotting fails.

    Side Effects:
        - Logs the analysis in the MongoDB `{business_id}notebook` collection:
            - Analysis type: "Boxplot"
            - Associated user and business ID
            - File metadata (name, dimensions)
            - UTC timestamp

    Notes:
        - Uses `seaborn.boxplot` to visualize statistical distribution.
        - All numeric columns are plotted side by side for comparison.
    """
    # Retrieve session data for the authenticated user and their associated business
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Validate session: Ensure user is authenticated and business ID is present
    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    # Connect to the MongoDB collection specific to the business
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-boxplot')
        elif 'sheet-url-boxplot' in request.form and request.form['sheet-url-boxplot'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_boxplot = request.form['sheet-url-boxplot'].strip()
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_boxplot)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        # Select numeric columns
        numeric_cols = df.select_dtypes(include='number').columns
        if len(numeric_cols) == 0:
            print("There are no numeric columns in the file.")
            flash("There are no numeric columns in the file.", "warning")
            return redirect(url_for('index'))

        # Create figure with subplots: 1 for the general view + N for individual plots
        total_plots = 1 + len(numeric_cols)  # 1 geral + individuais
        fig, axs = plt.subplots(total_plots, 1, figsize=(12, 4 * total_plots))

        # Ensure axs is always iterable
        if total_plots == 1:
            axs = [axs]

        # General plot
        sns.boxplot(data=df[numeric_cols], ax=axs[0])
        axs[0].set_title('Boxplot - All Numeric Columns', fontsize=14)
        axs[0].set_ylabel("Values")

        # Individual plots
        for ax, col in zip(axs[1:], numeric_cols):
            sns.boxplot(y=df[col], ax=ax, width=0.3)
            ax.set_title(f'Boxplot - {col}', fontsize=14)
            ax.set_ylabel(col)

        plt.tight_layout()

        # Convert to base64
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

        # Register
        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"

        db_business[collection_name].insert_one({
            "dataanalysis": "Boxplot",
            "username": user_name,
            "business_id": business_id,
            "file_name": file.filename if file else sheet_url_boxplot,
            "file_lines": file_lines,
            "file_columns": file_columns,
            "accessed_at": datetime.now(timezone.utc)
        })

        return {"image": img_base64}
    
    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/correlationmatrix', methods=['GET', 'POST'])
@login_required
def correlationmatrix():
    """
    Generate and return a correlation matrix heatmap from uploaded data.

    This endpoint receives a CSV file or Google Sheets URL, computes the 
    correlation matrix between numeric columns, and generates a heatmap 
    using seaborn. The image is returned as a base64-encoded PNG for rendering
    on the frontend.

    Authentication:
        Requires a valid user session with `username` and `business_id`.

    Methods:
        GET, POST

    Request (POST):
        - Upload field: "file" (CSV file)
        - OR form field: "sheet-url-correlationmatrix" (Google Sheets URL)

    Returns:
        dict: JSON object containing:
            - "image" (str): Base64-encoded PNG of the correlation heatmap.

    Raises:
        400 Bad Request: If no input file or URL is provided.
        500 Internal Server Error: If there are data processing or rendering issues.

    Side Effects:
        - Logs the following in MongoDB `{business_id}notebook` collection:
            - Analysis type: "Correlation Matrix"
            - Username and business ID
            - File name or URL
            - Number of lines and columns in the dataset
            - Timestamp of access (UTC)

    Notes:
        - Only numeric columns are used for correlation calculation.
        - `seaborn.heatmap` is used to render the matrix.
    """
    # Retrieve user session data (username and associated business ID)
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Validate authentication and session integrity
    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    # Access the specific business collection in MongoDB
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-correlationmatrix')
        elif 'sheet-url-correlationmatrix' in request.form and request.form['sheet-url-correlationmatrix'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_correlationmatrix = request.form['sheet-url-correlationmatrix'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_correlationmatrix)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        # Generate the correlation matrix for numeric-only columns
        plt.figure(figsize=(10, 8))
        # Plot the correlation matrix as a heatmap using seaborn
        corr = df.corr(numeric_only=True)
        sns.heatmap(corr, annot=True, cmap='coolwarm')
        plt.title('Correlation Matrix')
        img = io.BytesIO() # Save the figure to a memory buffer
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8') # Encode the image in base64 to send it in a JSON response

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Correlation Matrix",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_correlationmatrix,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        # Return the base64-encoded image as JSON
        return {"image": img_base64}

    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/scatterplot', methods=['GET', 'POST'])
@login_required
def scatterplot():
    """
    Generate and return scatter plots for all numeric column pairs in a dataset.

    This endpoint creates scatter plots comparing every pair of numeric columns 
    in an uploaded CSV or Google Sheets file. The plots are vertically stacked 
    and returned as a single base64-encoded PNG image.

    Authentication:
        Requires a valid session with `username` and `business_id`.

    Methods:
        GET, POST

    Request (POST):
        - Upload field: "file" (CSV file)
        - OR form field: "sheet-url-scatterplot" (Google Sheets URL)

    Returns:
        dict: JSON object containing:
            - "image" (str): Base64-encoded PNG containing all scatter plots.

    Raises:
        400 Bad Request: If input file is missing or contains no numeric data.
        500 Internal Server Error: On data processing or charting failures.

    Side Effects:
        - Logs metadata in MongoDB `{business_id}notebook` collection:
            - Analysis type: "Scatter Plot"
            - Username and business ID
            - File name or URL
            - File dimensions (lines and columns)
            - UTC timestamp of access

    Notes:
        - Uses `seaborn.scatterplot` for rendering.
        - If only one numeric column pair exists, only one plot is generated.
        - Extra subplots are removed if not needed.
    """
    # Retrieve user and business session data
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Verify user authentication and business context
    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    # Access the MongoDB collection specific to the user's business
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-scatterplot')
        elif 'sheet-url-scatterplot' in request.form and request.form['sheet-url-scatterplot'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_scatterplot = request.form['sheet-url-scatterplot'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_scatterplot)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        numeric_cols = df.select_dtypes(include='number').columns

        if len(numeric_cols) == 0:
            print("There is not numeric columns in yhe file")
            flash("There is not numeric columns in yhe file", "warning")
            return redirect(url_for('index'))

        col_pairs = list(combinations(numeric_cols, 2))
        total_plots = len(col_pairs)
        fig, axes = plt.subplots(total_plots, 1, figsize=(12, 6 * total_plots), constrained_layout=True)

        if total_plots == 1:
            axes = [axes]

        for i, (x_col, y_col) in enumerate(col_pairs):
            ax = axes[i]
            sns.scatterplot(data=df, x=x_col, y=y_col, ax=ax)
            ax.set_title(f'{x_col} vs {y_col}')
            ax.tick_params(axis='x', rotation=45)

        for j in range(i + 1, len(axes)):
            fig.delaxes(axes[j])

        plt.tight_layout()

        # Save the plot to an in-memory buffer
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8') # Encode the image in base64 for client-side rendering

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Scatter Plot",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_scatterplot,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )
        
        # Return the image as a base64-encoded string in JSON format
        return {"image": img_base64}

    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/linechart', methods=['GET', 'POST'])
@login_required
def linechart():
    """
    Endpoint to generate and return a line chart from a user-uploaded CSV file.

    Methods:
        GET, POST

    Returns:
        JSON object containing a base64-encoded PNG image of the line chart.

    Functionality:
        - Validates user authentication and business association.
        - Accepts a CSV file with one or more numeric columns.
        - Plots all numeric columns in the file on a single line chart using pandas and matplotlib.
        - Converts the resulting chart image into a base64 string for web display.
    """
    # Retrieve the logged-in user's name and their associated business ID from the session
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Ensure the user is logged in and associated with a business
    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    # Retrieve the MongoDB collection specific to the business
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-linechart')
        elif 'sheet-url-linechart' in request.form and request.form['sheet-url-linechart'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_linechart = request.form['sheet-url-linechart'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_linechart)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        numeric_df = df.select_dtypes(include='number')
        num_columns = len(numeric_df.columns)
        total_plots = 1 + num_columns 
        fig, axs = plt.subplots(total_plots, 1, figsize=(12, 6 * total_plots), constrained_layout=True)

        if total_plots == 1:
            axs = [axs]

        numeric_df.plot(ax=axs[0])
        axs[0].set_title('Line Chart (All Columns)')
        axs[0].set_xlabel('Index')
        axs[0].set_ylabel('Values')

        for idx, column in enumerate(numeric_df.columns):
            axs[idx + 1].plot(numeric_df.index, numeric_df[column], label=column)
            axs[idx + 1].set_title(f'Line Chart: {column}')
            axs[idx + 1].set_xlabel('Index')
            axs[idx + 1].set_ylabel(column)
            axs[idx + 1].legend()

        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8') # Encode the image as a base64 string to return in the response

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Line Chart",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_linechart,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )
        
        # Return the encoded image in JSON format
        return {"image": img_base64}
    
    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/piechart', methods=['GET', 'POST'])
@login_required
def piechart():
    """
    Generate and return pie chart(s) from a CSV file or Google Sheets URL.

    This endpoint allows users to upload a CSV or provide a Google Sheets URL
    containing at least one categorical and one numeric column. It generates
    pie charts that summarize the distribution of numeric values grouped by
    the categorical column(s). The resulting chart(s) are returned as a 
    base64-encoded PNG image wrapped in a JSON response.

    Authentication:
        Requires user to be logged in and associated with a valid `business_id`.

    Methods:
        GET, POST

    Request (POST):
        - One of the following inputs:
            - A file upload field named "file" containing a valid `.csv` file.
            - A form field named "sheet-url-piechart" containing a valid Google Sheets URL.

    Returns:
        dict: JSON response containing:
            - "image" (str): A base64-encoded PNG image with one or more pie charts.
              Example:
              {
                  "image": "<base64 PNG string>"
              }

    Raises:
        400 Bad Request: If the file or sheet is invalid or missing.
        500 Internal Server Error: On unexpected data processing errors.

    Side Effects:
        - Logs analysis metadata to MongoDB in collection `{business_id}notebook`:
            - Analysis type: "Pie Chart"
            - Username and business_id
            - File name or sheet URL
            - Number of rows and columns in the dataset
            - Timestamp of access

    Notes:
        - Only combinations of categorical and numeric columns with >1 group are included.
        - Each combination produces one pie chart.
        - If no valid combination is found, an error image is returned instead.
    """
    # Retrieve username and business ID from the session
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Ensure that both username and business ID are present
    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    # Access the business-specific collection in MongoDB
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-piechart')
        elif 'sheet-url-piechart' in request.form and request.form['sheet-url-piechart'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_piechart = request.form['sheet-url-piechart'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_piechart)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        categorical_columns = df.select_dtypes(include=['object', 'category']).columns
        numeric_columns = df.select_dtypes(include=['number']).columns

        if len(categorical_columns) == 0 or len(numeric_columns) == 0:
            return jsonify({"image": generate_error_image("The CSV must contain at least one categorical column and one numerical column.")})

        combinations = []
        for cat_col in categorical_columns:
            for num_col in numeric_columns:
                grouped_data = df.groupby(cat_col)[num_col].sum().sort_values(ascending=False)
                if grouped_data.shape[0] > 1:
                    combinations.append((cat_col, num_col, grouped_data))

        for num_col in numeric_columns:
            counts = df[num_col].value_counts().sort_values(ascending=False)
            if counts.shape[0] > 1:
                combinations.append((cat_col, num_col, counts))

        if not combinations:
            return jsonify({"image": generate_error_image("No pie chart could be generated with the provided data.")})

        num_charts = len(combinations)

        rows = num_charts
        fig, axes = plt.subplots(rows, 1, figsize=(12, 6 * rows), constrained_layout=True)

        # Garante que seja uma lista mesmo se houver só 1 gráfico
        if num_charts == 1:
            axes = [axes]

        for idx, (cat_col, num_col, grouped_data) in enumerate(combinations):
            ax = axes[idx]
            ax.pie(
                grouped_data.values,
                labels=grouped_data.index,
                autopct='%1.1f%%',
                startangle=140
            )
            ax.set_title(f"{cat_col} vs {num_col}", fontsize=10)

        # Remover subplots extras se existirem
        for j in range(len(combinations), len(axes)):
            fig.delaxes(axes[j])

        fig.tight_layout()
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8') # Encode the image as a base64 string for JSON transport

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Pie Chart",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_piechart,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        # Return the encoded image wrapped in a JSON object
        return {"image": img_base64}
    
    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/olap_slice_dice', methods=['POST'])
@login_required
def olap_slice_dice():
    """
    Perform an OLAP 'slice and dice' operation.
    Expects a CSV with multiple columns; slices data based on a selected category and value.

    Returns:
        JSON with base64-encoded bar chart of a subset of data.
    """
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-olap_slice_dice')
        elif 'sheet-url-olap-slice-dice' in request.form and request.form['sheet-url-olap-slice-dice'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_olap_slice_dice = request.form['sheet-url-olap-slice-dice'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_olap_slice_dice)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        # Assume we slice by the first categorical column and aggregate second numeric
        cat_cols = df.select_dtypes(include='object').columns
        num_cols = df.select_dtypes(include='number').columns

        if len(cat_cols) == 0 or len(num_cols) == 0:
            return {"error": "CSV must include at least one categorical and one numeric column."}

        # Generate all possible categorical × numerical combinations
        combinations = []
        for cat in cat_cols:
            for num in num_cols:
                grouped = df.groupby(cat)[num].sum().sort_values(ascending=False)
                if grouped.shape[0] > 1:
                    combinations.append((cat, num, grouped))

        if not combinations:
            return {"error": "No valid categorical × numeric combinations found for Slice & Dice."}

        total = len(combinations)
        rows = total
        fig, axes = plt.subplots(rows, 1, figsize=(12, 6 * rows), constrained_layout=True)

        if total == 1:
            axes = [axes]

        for idx, (cat, num, grouped) in enumerate(combinations):
            ax = axes[idx]
            grouped.head(10).plot(kind='bar', ax=ax)
            ax.set_title(f"Sum of {num} by {cat}", fontsize=10)
            ax.set_xlabel(cat)
            ax.set_ylabel(num)

        # Delete unused axes (in case the number of plots < total subplots)
        for j in range(len(combinations), len(axes)):
            fig.delaxes(axes[j])

        fig.tight_layout()
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Olap Slice & Dice",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_olap_slice_dice,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        return {"image": img_base64}

    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/olap_drilldown', methods=['POST'])
@login_required
def olap_drilldown():
    """
    Perform an OLAP Drill-Down analysis on a datetime column grouped by month.

    This endpoint allows authenticated users to upload a CSV file or provide a 
    Google Sheets URL to perform an OLAP-style drill-down operation. It detects 
    a valid date column and one or more numeric columns, then aggregates the 
    numeric data by month and returns a time series chart (line plot) in base64 format.

    The chart and relevant metadata (e.g., file name, number of lines and columns) 
    are logged into a MongoDB collection specific to the business context.

    Authentication:
        Requires an active user session with 'username' and 'business_id' set.

    Request (POST):
        Form Data:
            - file (FileStorage, optional): Uploaded CSV file.
            - sheet-url-olap-drilldown (str, optional): Public Google Sheets URL.
        
        One of the above fields must be provided.

    Returns:
        flask.Response: JSON with the following structure:
            - On success:
                {
                    "image": "<base64-encoded PNG string>"
                }
            - On error:
                {
                    "image": "<base64 image with error message>"
                }

    Example Errors:
        - Missing or invalid file/URL input
        - No valid datetime column detected
        - No numeric columns found
        - Failure while generating charts

    Side Effects:
        - Inserts a log entry into the collection `<business_id>notebook` in MongoDB
          with analysis type "Olap Drilldown".

    Raises:
        401 Unauthorized: If session is missing user or business ID.
        500 Internal Server Error: If processing or chart generation fails.
    """
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        msg = "User not authenticated or business ID missing."
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": msg}), 401
        
        print(msg)
        flash(msg, 'danger')
        return redirect(url_for('login'))

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-olap_drilldown')
        elif 'sheet-url-olap-drilldown' in request.form and request.form['sheet-url-olap-drilldown'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_olap_drilldown = request.form['sheet-url-olap-drilldown'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_olap_drilldown)
            if not match:
                raise ValueError("URL inválida do Google Sheets")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))

        # Detect date column
        date_col = None
        for col in df.columns:
            if pd.api.types.is_numeric_dtype(df[col]):
                continue  # Ignore numeric columns like '202001'
            try:
                parsed = pd.to_datetime(df[col], errors='coerce', infer_datetime_format=True)
                not_null = parsed.notnull().sum()
                unique_dates = parsed.dropna().nunique()

                if not_null >= len(df) * 0.3 and unique_dates >= 3:
                    df[col] = parsed
                    date_col = col
                    break
            except Exception:
                continue

        if not date_col:
            return jsonify({"image": generate_error_image("The CSV must contain at least one column with valid dates.")})

        # Detect numeric columns (excluding the date column)
        num_cols = [
            col for col in df.columns
            if col != date_col and pd.api.types.is_numeric_dtype(df[col])
        ]

        if not num_cols:
            return jsonify({"image": generate_error_image("The CSV must contain at least one numeric column in addition to the date column.")})

        try:
            df[date_col] = pd.to_datetime(df[date_col])
            df['month'] = df[date_col].dt.to_period('M')
            n = len(num_cols)
            rows = n
            fig, axes = plt.subplots(rows, 1, figsize=(12, 6 * rows), constrained_layout=True)

            if n == 1:
                axes = [axes]

            for i, col in enumerate(num_cols):
                try:
                    monthly_summary = df.groupby('month')[col].sum()
                    monthly_summary.index = monthly_summary.index.to_timestamp()

                    ax = axes[i]
                    monthly_summary.plot(marker='o', ax=ax)
                    ax.set_title(f"Monthly Drill-Down: {col}", fontsize=12)
                    ax.set_ylabel(col)
                    ax.set_xlabel("Month")
                    ax.grid(True)

                except Exception as e:
                    return jsonify({"error": "Error generating the chart."}), 500

            for j in range(i + 1, len(axes)):
                fig.delaxes(axes[j])

            plt.tight_layout()
            img = io.BytesIO()
            plt.savefig(img, format='png')
            img.seek(0)
            plt.close()
            img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

            file_lines = len(df) + 1
            file_columns = df.shape[1]
            collection_name = f"{business_id}notebook"
            db_business[collection_name].insert_one(
                    {
                    "dataanalysis": "Olap Drilldown",
                    "username": user_name,
                    "business_id": business_id,
                    "file_name": file.filename if file else sheet_url_olap_drilldown,
                    "file_lines": file_lines,
                    "file_columns": file_columns,
                    "accessed_at": datetime.now(timezone.utc)
                    }
                )

            return jsonify({"image": img_base64})

        except Exception as e:
            return jsonify({"image": generate_error_image("Error generating the chart.")})
    
    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/olap_pivot', methods=['POST'])
@login_required
def olap_pivot():
    """
    Perform OLAP-like pivot analysis from a CSV file or Google Sheets URL and return a heatmap image.

    This route processes a CSV file or a Google Sheets URL submitted by the user.
    It generates multiple pivot tables by aggregating numeric columns across combinations
    of categorical columns and returns the result as a base64-encoded heatmap image.

    The function also logs access metadata such as filename, number of lines, and columns 
    into a MongoDB collection specific to the business context.

    Requires the user to be authenticated.

    Request (POST Form Data):
        file (FileStorage, optional): A CSV file uploaded by the user.
        sheet-url-olap-pivot (str, optional): URL of a public Google Sheets document.

    Session:
        username (str): Authenticated user's username (must be set).
        business_id (str): Business identifier used for database context (must be set).

    Returns:
        dict: JSON object containing the base64-encoded PNG image of the heatmap.
              Example: {"image": "data:image/png;base64,..."}

    Raises:
        Redirect: If no file or URL is provided, or if validation fails.
        Exception: If any processing or analysis fails, returns a fallback image indicating an error.
    """
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name or not business_id:
        print("User not authenticated or missing business ID.")
        flash("User not authenticated or missing business ID.", 'danger')
        return redirect(url_for('login'))

    try:
        # Case 1: CSV file upload
        # -----------------------------------------------
        # If a CSV file is provided via the 'file' field in the request
        file = request.files.get("file")
        if 'file' in request.files and request.files['file'].filename != '':
            # Read the file from the request
            file = request.files['file']
            # Load the CSV file into a pandas DataFrame
            df = pd.read_csv(file)

        # Case 2: Google Sheets URL is provided via form field
        # -----------------------------------------------------
        # If a Google Sheets URL is provided in the form data (field name: 'sheet-url-olap_pivot')
        elif 'sheet-url-olap-pivot' in request.form and request.form['sheet-url-olap-pivot'].strip() != '':
            # Retrieve and clean the submitted URL
            sheet_url_olap_pivot = request.form['sheet-url-olap-pivot'].strip()
            
            # Create credentials from service account info
            credentials = Credentials.from_service_account_info(SERVICE_ACCOUNT_INFO, scopes=SCOPES)
            # Authorize client using gspread and credentials
            client = gspread.authorize(credentials)

            # Extract spreadsheet ID from the provided URL using regex
            match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", sheet_url_olap_pivot)
            if not match:
                raise ValueError("Invalid Google Sheets URL")

            # Get the spreadsheet ID from the regex match
            spreadsheet_id = match.group(1)
            # Open the spreadsheet by ID and access the first sheet/tab
            sheet = client.open_by_key(spreadsheet_id).sheet1  # pegar primeira aba
            # Get all records (rows) from the sheet
            data = sheet.get_all_records()
            # Convert the data into a pandas DataFrame
            df = pd.DataFrame(data)

        # Case 3: No file or URL provided
        # --------------------------------
        else:
            # Show a warning message to the user
            print(f"Please upload a CSV file or a valid Google Sheets URL.")
            flash("Please upload a CSV file or a valid Google Sheets URL.", "warning")
            # Redirect the user to the home page
            return redirect(url_for('index'))
        
        cat_cols = df.select_dtypes(include='object').columns
        num_cols = df.select_dtypes(include='number').columns

        if len(cat_cols) < 1 or len(num_cols) == 0:
            print("CSV must contain at least one categorical and one numeric column.")
            flash("CSV must contain at least one categorical and one numeric column.", "error")
            return redirect(url_for('data_analysis'))
        
        cat_combinations = list(itertools.combinations(cat_cols, 2)) + [(col,) for col in cat_cols]
        pivot_tasks = [(num_col, cat_combo) for num_col in num_cols for cat_combo in cat_combinations]
        n_cols = 1
        n_rows = math.ceil(len(pivot_tasks) / n_cols)
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(n_cols * 12, n_rows * 6))
        axes = axes.flatten()

        for idx, (num_col, cat_combo) in enumerate(pivot_tasks):
            ax = axes[idx]

            try:
                pivot_table = pd.pivot_table(
                    df,
                    values=num_col,
                    index=cat_combo[0],
                    columns=cat_combo[1] if len(cat_combo) > 1 else None,
                    aggfunc='sum',
                    fill_value=0
                )

                sns.heatmap(pivot_table, annot=True, fmt=".0f", cmap="Blues", ax=ax)
                ax.set_title(f"{num_col} by {', '.join(cat_combo)}", fontsize=10)

            except Exception as e:
                print(f"[WARNING] Skipping {num_col} with {cat_combo}: {e}")
                ax.axis('off')
                ax.set_title(f"Error: {num_col} by {', '.join(cat_combo)}", fontsize=10)

        for idx in range(len(pivot_tasks), len(axes)):
            axes[idx].axis('off')

        plt.tight_layout()
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        plt.close()
        img.seek(0)
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

        file_lines = len(df) + 1
        file_columns = df.shape[1]
        collection_name = f"{business_id}notebook"
        db_business[collection_name].insert_one(
                {
                "dataanalysis": "Olap Pivot",
                "username": user_name,
                "business_id": business_id,
                "file_name": file.filename if file else sheet_url_olap_pivot,
                "file_lines": file_lines,
                "file_columns": file_columns,
                "accessed_at": datetime.now(timezone.utc)
                }
            )

        return {"image": img_base64}
    
    except Exception as e:
        return jsonify({"image": generate_error_image("Error processing the data. Please check your file or URL.")})

@app.route('/visual_data', methods=['GET', 'POST'])
@login_required
def visual_data():
    """
    Handle visualization of uploaded CSV data.

    This route allows authenticated users to upload a CSV file, which is then 
    parsed into a pandas DataFrame, analyzed, and stored in MongoDB.
    The analysis results and a preview of the data are displayed.

    GET:
        Render the visual_data.html page for file upload and display.

    POST:
        - Process uploaded CSV file.
        - Save DataFrame to MongoDB.
        - Analyze the data and render results.
        - Log user access metadata.

    Returns:
        Response: Rendered HTML page (visual_data.html).
    """
    # Retrieve user and business from session for authentication
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Redirect unauthenticated users
    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    business_collection = db_business[business_id] # Fetch user details from MongoDB
    user = business_collection.find_one({"username": user_name})

    # Handle CSV file upload
    if request.method == 'POST':
        file = request.files.get('fileInput')

        # Check if a CSV file was uploaded
        if file and file.filename.endswith('.csv'):
            try:
                # Read CSV into a DataFrame
                df = pd.read_csv(file)
                sheet_title = os.path.splitext(file.filename)[0]
                worksheet_title = "Main Sheet"
                save_dataframe_to_mongo(df) # Save DataFrame to MongoDB and perform analysis
                analysis = analyze_dataframe(df) # Extended analysis
                df_html = df.to_html(classes="dataframe", index=False) # Convert DataFrame to HTML for rendering

                # Attempt to log this visual access in the "notebook" collection
                try:
                    file_or_url = request.form.get('file_name_value')
                    file_lines = int(request.form.get('file_lines_value')) + 1
                    file_columns = request.form.get('file_columns_value')
                    collection_name = f"{business_id}notebook"
                    db_business[collection_name].insert_one(
                            {
                            "dataanalysis": "Visual Data",
                            "username": user_name,
                            "business_id": business_id,
                            "file_name": file_or_url,
                            "file_lines": file_lines,
                            "file_columns": file_columns,
                            "accessed_at": datetime.now(timezone.utc)
                            }
                        )

                except Exception as e:
                    print(f"Could not save access log to MongoDB: {e}")
                    flash("Could not save access log to Database.", 'danger')

                # Render template with data and analysis
                return render_template('visual_data.html',
                                       business_id=business_id,
                                       user_name=user_name,
                                       user_data=user,
                                       df_html=df_html,
                                       analysis=analysis,
                                       sheet_info={
                                            "url": "Not available",
                                            "sheet_id": "Not available",
                                            "sheet_title": sheet_title,
                                            "worksheet_title": worksheet_title
                                        })
            except Exception as e:
                print(f"Error processing file: {e}")
                flash(f"Error processing file: {e}", "danger")
                return redirect(url_for('visual_data'))

        else:
            print("Please upload a valid CSV file.")
            flash("Please upload a valid CSV file.", "danger")
            return redirect(url_for('visual_data'))

    # GET request: render the template without data
    return render_template('visual_data.html',
                           business_id=business_id,
                           user_name=user_name,
                           user_data=user)

@app.route('/visual_data_googlesheets', methods=['GET', 'POST'])
@login_required
def visual_data_googlesheets():
    """
    Handle visualization of data from a Google Sheets URL.

    This route lets authenticated users submit a Google Sheets URL,
    from which data is loaded, analyzed, and rendered. The access 
    information is stored in the MongoDB notebook log.

    GET:
        Render the form to input a Google Sheets URL.

    POST:
        - Load the Google Sheet into a pandas DataFrame.
        - Perform data analysis and generate metadata.
        - Store analysis info and user access log in MongoDB.
        - Display the analyzed data and visual report.

    Returns:
        Response: Rendered HTML page (visual_data_googlesheets.html).
    """
    # Validate user authentication from session
    user_name = session.get('username')
    business_id = session.get('business_id')

    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Ensure business_id is present
    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Retrieve the current user document
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})

    # Handle the Google Sheets submission
    if request.method == 'POST':
        sheet_url = request.form.get('sheet_url')

        if not sheet_url:
            print("Please provide a Google Sheets URL.")
            flash("Please provide a Google Sheets URL.", "danger")
            return redirect(url_for('visual_data_googlesheets'))

        try:
            # Load sheet into DataFrame and extract metadata
            df, sheet_info = load_google_sheet_visual_data(sheet_url)
            analysis = analyze_dataframe_googlesheets(df)
            analysis["info"]["url"] = sheet_url
            df_html = df.to_html(classes="dataframe", index=False)

            # Prepare access log
            file_lines = len(df) + 1
            file_columns = df.shape[1]
            collection_name = f"{business_id}notebook"

            # Store analysis access log into MongoDB
            db_business[collection_name].insert_one(
                    {
                    "dataanalysis": "Visual Data",
                    "username": user_name,
                    "business_id": business_id,
                    "file_name": sheet_url,
                    "file_lines": file_lines,
                    "file_columns": file_columns,
                    "accessed_at": datetime.now(timezone.utc)
                    }
                )
            
            # Render visualization with analysis results
            return render_template("visual_data_googlesheets.html",
                                   analysis=analysis,
                                   df_html=df_html,
                                   sheet_info=sheet_info)
        
        except Exception as e:
            print(f"Error: {str(e)}")
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for('visual_data_googlesheets'))

    # GET request: render empty analysis page
    return render_template("visual_data_googlesheets.html", analysis=None)

@app.route('/notebook', methods=['GET', 'POST'])
@login_required
def notebook():
    """
    Display recent notebook activity logs and visual analytics for the logged-in user.

    This route allows users to review the history of executed data analyses and 
    see visual representations of their usage patterns. Users can filter results by 
    analysis type and date range, and pagination is applied to limit results to 
    50 entries per page. The route also dynamically generates bar, line, and pie charts.

    GET:
        - Retrieve notebook entries from MongoDB.
        - Apply filters from query parameters (dataanalysis, start_date, end_date).
        - Generate charts and render the template.

    POST:
        Not applicable. No file handling or form submission is processed here.

    Query Parameters:
        dataanalysis (str, optional): Filter entries by data analysis type.
        start_date (str, optional): Start date filter in YYYY-MM-DD format.
        end_date (str, optional): End date filter in YYYY-MM-DD format.
        page (int, optional): Page number for paginated results (default is 1).

    Returns:
        flask.Response: Rendered HTML page (notebook.html) with:
            - Filtered notebook entries (max 50).
            - Total page count and current page.
            - Drop-down options for filtering by analysis.
            - Base64-encoded bar, line, and pie charts.
    """
    # Retrieve session data to identify the authenticated user and business context
    user_name = session.get('username')
    business_id = session.get('business_id')

    # Redirect to login if user or business session data is missing
    if not user_name:
        print("User not authenticated. Redirecting to login.")
        flash("User not authenticated. Redirecting to login.", 'danger')
        return redirect(url_for('login'))

    if not business_id:
        print("Business ID not found in session. Redirecting to login.")
        flash("Business ID not found in session. Redirecting to login.", 'danger')
        return redirect(url_for('login'))
    
    # Access user document and notebook activity collection
    business_collection = db_business[business_id]
    user = business_collection.find_one({"username": user_name})
    collection_name = f"{business_id}notebook"
    notebook_collection = db_business[collection_name]

    # === Filter parameters from request ===
    dataanalysis_filter = request.args.get('dataanalysis')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    query = {"username": user_name}

    # Apply dataanalysis type filter
    if dataanalysis_filter:
        query["dataanalysis"] = dataanalysis_filter

    # Apply date range filter if both dates are provided
    if start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query["accessed_at"] = {"$gte": start_date, "$lte": end_date}

        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")
            flash("Invalid date format. Please use YYYY-MM-DD.", 'warning')

    # Handle pagination parameters
    page = int(request.args.get("page", 1))

    if page > 12:
        page = 12

    per_page = 50
    skip = (page - 1) * per_page
    total_entries = notebook_collection.count_documents(query)
    total_pages = (total_entries + per_page - 1) // per_page

    if total_pages > 12:
        total_pages = 12

    # Query the notebook entries with applied filters and pagination
    notebook_entries = list(
        notebook_collection.find(query).sort("accessed_at", -1).skip(skip).limit(per_page)
    )
    
    # Get all distinct analysis types (for the dropdown filter)
    all_dataanalysis = db_business[collection_name].distinct("dataanalysis", {"username": user_name})

    # Load full notebook activity into a DataFrame for chart generation
    df = pd.DataFrame(notebook_collection.find({"username": user_name}))

    if not df.empty:
        df["accessed_at"] = pd.to_datetime(df["accessed_at"])
        df["month"] = df["accessed_at"].dt.to_period("M").astype(str)

        # === Generate Bar Chart: Top analysis types ===
        bar_img = io.BytesIO()
        df["dataanalysis"].value_counts().plot(kind="bar", color="#1E90FF", figsize=(12, 6))
        plt.xlabel("Data Analysis")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(bar_img, format="png", facecolor='#f8f9fa')
        plt.close()
        bar_base64 = base64.b64encode(bar_img.getvalue()).decode()

        # === Generate Line Chart: Monthly usage trend ===
        line_img = io.BytesIO()
        df.groupby("month").size().plot(kind="line", marker="o", color="#1465bb", figsize=(12, 6))
        plt.xlabel("Month")
        plt.ylabel("Usage Count")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(line_img, format="png", facecolor='#f8f9fa')
        plt.close()
        line_base64 = base64.b64encode(line_img.getvalue()).decode()

        # === Generate Pie Chart: Usage distribution ===
        pie_img = io.BytesIO()
        df["dataanalysis"].value_counts().plot(kind="pie", autopct="%1.1f%%", startangle=140, figsize=(8, 8))
        plt.ylabel("")
        plt.tight_layout()
        plt.savefig(pie_img, format="png", facecolor='#f8f9fa')
        plt.close()
        pie_base64 = base64.b64encode(pie_img.getvalue()).decode()

    else:
        bar_base64 = line_base64 = pie_base64 = None # If no data found, skip chart generation

    # Render the notebook template with all required context
    return render_template(
        "notebook.html",
        business_id=business_id,
        user_name=user_name,
        user_data=user,
        notebook_entries=notebook_entries,
        all_dataanalysis=all_dataanalysis,
        dataanalysis_filter=dataanalysis_filter,
        start_date=start_date_str,
        end_date=end_date_str,
        current_page=page,
        total_pages=total_pages,
        bar_chart=bar_base64,
        line_chart=line_base64,
        pie_chart=pie_base64
    )

@app.route("/error")
def error():
    """
    Display a generic error page.

    This route can be used to show a friendly error message when an issue occurs 
    elsewhere in the application.

    Returns:
        flask.Response: Rendered HTML error page (error.html).
    """
    return render_template('error.html')

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(host="0.0.0.0", port=5000, debug=False)
