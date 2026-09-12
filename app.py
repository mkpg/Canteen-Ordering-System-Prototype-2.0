"""
Automated Canteen Ordering System
Flask Backend with MongoDB
Production-Ready Version
"""

import os
import re
import certifi
import base64
import random
import string
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from gridfs import GridFS
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import json
import urllib.request
import urllib.error
from flask_compress import Compress
from dotenv import load_dotenv
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_mail import Mail, Message

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
Compress(app)  # Enable gzip compression for all responses

# ==================== SECURE CONFIGURATION ====================
# All sensitive data MUST be in environment variables
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())
ADMIN_CODE = os.getenv('ADMIN_CODE', 'Your_Admin_Code')
CORE_ADMIN_EMAIL = os.getenv('CORE_ADMIN_EMAIL', 'Your_Admin_mail')
CORE_ADMIN_PASSWORD = os.getenv('CORE_ADMIN_PASSWORD', 'yoUr_admin_password')
CORE_ADMIN_USERNAME = os.getenv('CORE_ADMIN_USERNAME', 'Your_admin_userName')

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# MongoDB setup with SSL certificate for Atlas - OPTIMIZED for performance
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client_kwargs = {
    'maxPoolSize': 50,
    'minPoolSize': 5,
    'serverSelectionTimeoutMS': 5000,
    'connectTimeoutMS': 10000,
    'socketTimeoutMS': 20000,
    'maxIdleTimeMS': 45000
}

# Only require SSL/TLS certificates if connecting to MongoDB Atlas cloud
if 'mongodb+srv://' in MONGO_URI:
    client_kwargs['tlsCAFile'] = certifi.where()

client = MongoClient(MONGO_URI, **client_kwargs)
db = client['canteen_app']
# Unused collections have been migrated to Neon PostgreSQL
# GridFS for storing uploaded images in MongoDB
fs = GridFS(db, collection='food_images')

# ==================== NEON POSTGRESQL SETUP ====================
# We will initialize SQLAlchemy for Neon alongside PyMongo.
# Eventually we can migrate collections over here.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('NEON_DATABASE_URL', 'sqlite:///fallback.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
sql_db = SQLAlchemy(app)

# ==================== SQLALCHEMY MODELS ====================

class OrganizationModel(sql_db.Model):
    __tablename__ = 'organizations'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True) # To store original MongoDB ObjectId
    name = sql_db.Column(sql_db.String(100), nullable=False)
    description = sql_db.Column(sql_db.Text, nullable=True)
    admin_code = sql_db.Column(sql_db.String(50), nullable=False)
    is_active = sql_db.Column(sql_db.Boolean, default=True)
    created_at = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)
    operating_hours_json = sql_db.Column(sql_db.Text, nullable=True)  # JSON: {start, end, all_day}

    def to_dict(self):
        import json as _json
        oh = {'start': '08:00', 'end': '20:00', 'all_day': False}
        if self.operating_hours_json:
            try:
                oh = _json.loads(self.operating_hours_json)
            except Exception:
                pass
        return {
            '_id': ObjectId(self.mongo_id) if self.mongo_id else self.id,
            'name': self.name,
            'description': self.description,
            'admin_code': self.admin_code,
            'is_active': self.is_active,
            'created_at': self.created_at,
            'operating_hours': oh
        }

class UserModel(sql_db.Model):
    __tablename__ = 'users'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True)
    first_name = sql_db.Column(sql_db.String(50), nullable=False)
    last_name = sql_db.Column(sql_db.String(50), nullable=False)
    username = sql_db.Column(sql_db.String(50), unique=True, nullable=False)
    password = sql_db.Column(sql_db.String(255), nullable=False)
    email = sql_db.Column(sql_db.String(100), unique=True, nullable=False)
    phone = sql_db.Column(sql_db.String(20), nullable=True)
    role = sql_db.Column(sql_db.String(20), nullable=False)
    is_admin = sql_db.Column(sql_db.Boolean, default=False)
    two_factor_enabled = sql_db.Column(sql_db.Boolean, default=False)
    avatar = sql_db.Column(sql_db.String(50), nullable=True, default='dosa')  # Indian food avatar key
    organization_id = sql_db.Column(sql_db.String(24), nullable=True) # References OrganizationModel.mongo_id
    created_at = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            '_id': ObjectId(self.mongo_id) if self.mongo_id else self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': self.username,
            'password': self.password,
            'email': self.email,
            'phone': self.phone,
            'role': self.role,
            'is_admin': self.is_admin,
            'two_factor_enabled': bool(self.two_factor_enabled),
            'avatar': self.avatar or 'dosa',
            'organization_id': ObjectId(self.organization_id) if self.organization_id else None,
            'created_at': self.created_at
        }

class MenuItemModel(sql_db.Model):
    __tablename__ = 'menu_items'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True)
    name = sql_db.Column(sql_db.String(100), nullable=False)
    description = sql_db.Column(sql_db.Text, nullable=True)
    price = sql_db.Column(sql_db.Float, nullable=False)
    category = sql_db.Column(sql_db.String(50), nullable=True)
    image_url = sql_db.Column(sql_db.Text, nullable=True)
    customization_hint = sql_db.Column(sql_db.Text, nullable=True)
    track_stock = sql_db.Column(sql_db.Boolean, default=False)
    stock = sql_db.Column(sql_db.Integer, default=0)
    low_stock_threshold = sql_db.Column(sql_db.Integer, default=5)
    is_available = sql_db.Column(sql_db.Boolean, default=True)
    organization_id = sql_db.Column(sql_db.String(24), nullable=True)
    created_at = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            '_id': str(self.mongo_id) if self.mongo_id else str(self.id),
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'category': self.category,
            'image_url': self.image_url,
            'customization_hint': self.customization_hint,
            'track_stock': self.track_stock,
            'stock': self.stock,
            'low_stock_threshold': self.low_stock_threshold,
            'is_available': self.is_available,
            'organization_id': self.organization_id,
            'created_at': self.created_at
        }

class OrderModel(sql_db.Model):
    __tablename__ = 'orders'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True)
    username = sql_db.Column(sql_db.String(50), nullable=False)
    product_name = sql_db.Column(sql_db.String(100), nullable=False)
    quantity = sql_db.Column(sql_db.Integer, nullable=False)
    price = sql_db.Column(sql_db.Float, nullable=False)
    total_price = sql_db.Column(sql_db.Float, nullable=False)
    customizations = sql_db.Column(sql_db.Text, nullable=True)
    status = sql_db.Column(sql_db.String(50), nullable=False, default='pending')
    organization_id = sql_db.Column(sql_db.String(24), nullable=True)
    order_time = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)
    payment_time = sql_db.Column(sql_db.DateTime, nullable=True)
    completed_time = sql_db.Column(sql_db.DateTime, nullable=True)
    scheduled_time = sql_db.Column(sql_db.DateTime, nullable=True)
    is_scheduled = sql_db.Column(sql_db.Boolean, default=False)
    payment_type = sql_db.Column(sql_db.String(50), nullable=True)

    def to_dict(self):
        return {
            '_id': str(self.mongo_id) if self.mongo_id else str(self.id),
            'username': self.username,
            'product_name': self.product_name,
            'quantity': self.quantity,
            'price': self.price,
            'total_price': self.total_price,
            'customizations': self.customizations,
            'status': self.status,
            'organization_id': self.organization_id,
            'order_time': self.order_time,
            'payment_time': self.payment_time,
            'completed_time': self.completed_time,
            'scheduled_time': self.scheduled_time,
            'is_scheduled': self.is_scheduled,
            'payment_type': self.payment_type
        }

class FeedbackModel(sql_db.Model):
    __tablename__ = 'feedback'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True)
    username = sql_db.Column(sql_db.String(50), nullable=False)
    rating = sql_db.Column(sql_db.Integer, nullable=False)
    comments = sql_db.Column(sql_db.Text, nullable=True)
    submitted_at = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            '_id': self.mongo_id or str(self.id),
            'id': self.id,
            'username': self.username,
            'rating': self.rating,
            'comments': self.comments,
            'submitted_at': self.submitted_at
        }

class PendingLoginModel(sql_db.Model):
    __tablename__ = 'pending_logins'
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    mongo_id = sql_db.Column(sql_db.String(24), unique=True, nullable=True)
    token = sql_db.Column(sql_db.String(100), nullable=False, unique=True)
    username = sql_db.Column(sql_db.String(50), nullable=False)
    organization_id = sql_db.Column(sql_db.String(24), nullable=True)
    email = sql_db.Column(sql_db.String(100), nullable=False)
    correct_number = sql_db.Column(sql_db.Integer, nullable=False)
    status = sql_db.Column(sql_db.String(50), default='pending')
    remember_device = sql_db.Column(sql_db.Boolean, default=False)
    created_at = sql_db.Column(sql_db.DateTime, default=datetime.utcnow)
    expires_at = sql_db.Column(sql_db.DateTime, nullable=False)
    ip_address = sql_db.Column(sql_db.String(50), nullable=True)

    user_agent = sql_db.Column(sql_db.Text, nullable=True)

    def to_dict(self):
        return {
            '_id': self.mongo_id or str(self.id),
            'id': self.id,
            'token': self.token,
            'username': self.username,
            'organization_id': self.organization_id,
            'email': self.email,
            'correct_number': self.correct_number,
            'status': self.status,
            'remember_device': self.remember_device,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }

# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    """Check if filename has an allowed image extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def verify_remember_device_cookie():
    """Return payload from remember-device cookie if valid; otherwise None."""
    token = request.cookies.get('remember_device')
    if not token:
        return None
    try:
        data = serializer.loads(
            token,
            salt='remember-device',
            max_age=60 * 60 * 24 * 30  # 30 days
        )
        return data
    except Exception:
        return None

def set_remember_device_cookie(resp, username, organization_id):
    """Attach a signed remember-device cookie to the response."""
    payload = {
        'u': username,
        'org': str(organization_id) if organization_id else '',
    }
    token = serializer.dumps(payload, salt='remember-device')
    resp.set_cookie(
        'remember_device',
        token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=False,  # set True when HTTPS is enforced
        samesite='Lax'
    )
    return resp

def clear_remember_device_cookie(resp):
    """Remove remember-device cookie from client."""
    resp.delete_cookie('remember_device')
    return resp

def complete_login(user, organization_id_str=None):
    """Finalize login session for a user and chosen organization."""
    session['username'] = user['username']
    session['active_organization_id'] = organization_id_str or None
    session.permanent = True

# Legacy MongoDB indexes removed as collections are now in PostgreSQL

# Force IPv4 socket resolution to fix Render [Errno 101] Network is unreachable on IPv6
import socket
_old_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4(*args, **kwargs):
    responses = _old_getaddrinfo(*args, **kwargs)
    ipv4_responses = [res for res in responses if res[0] == socket.AF_INET]
    return ipv4_responses if ipv4_responses else responses
socket.getaddrinfo = _getaddrinfo_ipv4

# Flask-Mail Configuration (credentials from environment)
mail_user = os.getenv('MAIL_USERNAME', '').strip()
mail_pass = os.getenv('MAIL_PASSWORD', '').replace(' ', '').strip()
mail_port = int(os.getenv('MAIL_PORT', 587))
mail_use_tls = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't', 'yes']
mail_use_ssl = os.getenv('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't', 'yes']

mail_sender = os.getenv('MAIL_DEFAULT_SENDER') or mail_user

app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=mail_port,
    MAIL_USE_TLS=mail_use_tls,
    MAIL_USE_SSL=mail_use_ssl,
    MAIL_USERNAME=mail_user,
    MAIL_PASSWORD=mail_pass,
    MAIL_DEFAULT_SENDER=mail_sender
)
mail = Mail(app)

def send_email_notification(to_email, subject, text_body, html_body=None):
    """Send transactional email via Brevo HTTPS REST API or fallback to Flask-Mail SMTP."""
    brevo_api_key = os.getenv('BREVO_API_KEY', '').strip()
    sender_email = os.getenv('MAIL_DEFAULT_SENDER') or os.getenv('MAIL_USERNAME', '').strip() or 'noreply@canteen.local'

    if brevo_api_key:
        try:
            url = "https://api.brevo.com/v3/smtp/email"
            payload = {
                "sender": {
                    "name": "CanteenOs",
                    "email": sender_email
                },
                "to": [{"email": to_email}],
                "subject": subject,
                "textContent": text_body,
                "htmlContent": html_body if html_body else f"<div style='font-family: sans-serif; white-space: pre-wrap;'>{text_body}</div>"
            }
            req_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    "accept": "application/json",
                    "api-key": brevo_api_key,
                    "content-type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in [200, 201, 202]:
                    return True
                else:
                    raise Exception(f"Brevo API returned status code {resp.status}")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode('utf-8')
            raise Exception(f"Brevo API error ({e.code}): {err_msg}")
        except Exception as e:
            raise e
    else:
        # Fallback to Flask-Mail SMTP
        msg = Message(
            subject,
            sender=sender_email,
            recipients=[to_email],
            body=text_body,
            html=html_body
        )
        mail.send(msg)
        return True

# Token serializer for reset links
serializer = URLSafeTimedSerializer(app.secret_key)

# ==================== 2FA HELPER FUNCTIONS ====================

def generate_2fa_token():
    """Generate a secure random token for 2FA email links."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def generate_2fa_numbers():
    """Generate 3 unique random numbers for 2FA verification (10-99)."""
    numbers = random.sample(range(10, 100), 3)
    correct_index = random.randint(0, 2)
    return numbers, numbers[correct_index]

def send_2fa_email(user, pending_login):
    """Send 2FA verification email with approve/deny buttons and number options."""
    approve_url = url_for('twofa_approve', token=pending_login['token'], _external=True)
    deny_url = url_for('twofa_deny', token=pending_login['token'], _external=True)
    
    # Generate URLs for each number option
    number_urls = []
    for num in pending_login['numbers']:
        url = url_for('twofa_verify_number', token=pending_login['token'], number=num, _external=True)
        number_urls.append((num, url))
    
    # HTML Email with styled buttons
    html_body = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
        <div style="max-width: 500px; margin: 0 auto; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.3);">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%); padding: 30px; text-align: center;">
                <h1 style="margin: 0; color: #1a1a2e; font-size: 24px;">🔐 Login Verification</h1>
                <p style="margin: 10px 0 0; color: #166534; font-size: 14px;">CanteenOs Security</p>
            </div>
            
            <!-- Content -->
            <div style="padding: 30px; color: #e5e5e5;">
                <p style="font-size: 16px; margin-bottom: 20px;">Hi <strong style="color: #4ade80;">{user['first_name']}</strong>,</p>
                
                <p style="font-size: 15px; line-height: 1.6;">Someone is trying to sign in to your CanteenOs account. If this was you, approve the login below.</p>
                
                <!-- Login Details Box -->
                <div style="background: rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; margin: 25px 0; border-left: 4px solid #4ade80;">
                    <p style="margin: 0 0 8px; font-size: 14px;"><strong>📅 Time:</strong> {pending_login['created_at'].strftime('%B %d, %Y at %I:%M %p')}</p>
                    <p style="margin: 0; font-size: 14px;"><strong>🌐 IP Address:</strong> {pending_login.get('ip_address', 'Unknown')}</p>
                </div>
                
                <!-- Option 1: Yes/No Buttons -->
                <p style="text-align: center; color: #a1a1aa; font-size: 13px; margin-bottom: 15px;">Was this you?</p>
                
                <div style="text-align: center; margin-bottom: 30px;">
                    <a href="{approve_url}" style="display: inline-block; background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%); color: #1a1a2e; text-decoration: none; padding: 14px 40px; border-radius: 8px; font-weight: bold; font-size: 16px; margin: 0 10px;">✓ Yes, it's me</a>
                    <a href="{deny_url}" style="display: inline-block; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; text-decoration: none; padding: 14px 40px; border-radius: 8px; font-weight: bold; font-size: 16px; margin: 0 10px;">✗ No, block this</a>
                </div>
                
                <!-- Divider -->
                <div style="border-top: 1px solid rgba(255,255,255,0.1); margin: 25px 0;"></div>
                
                <!-- Option 2: Number Verification -->
                <p style="text-align: center; color: #a1a1aa; font-size: 13px; margin-bottom: 15px;">Or click the number shown on your screen:</p>
                
                <div style="text-align: center;">
                    {''.join([f'<a href="{url}" style="display: inline-block; background: rgba(255,255,255,0.1); color: #e5e5e5; text-decoration: none; padding: 15px 25px; border-radius: 10px; font-weight: bold; font-size: 24px; margin: 0 8px; border: 2px solid rgba(74,222,128,0.3);">{num}</a>' for num, url in number_urls])}
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background: rgba(0,0,0,0.2); padding: 20px; text-align: center;">
                <p style="margin: 0; color: #71717a; font-size: 12px;">⚠️ If you didn't request this login, click "No, block this" immediately.</p>
                <p style="margin: 10px 0 0; color: #52525b; font-size: 11px;">This link expires in 10 minutes.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    # Plain text fallback
    text_body = f'''
Hi {user['first_name']},

Someone is trying to sign in to your CanteenOs account.

Time: {pending_login['created_at'].strftime('%B %d, %Y at %I:%M %p')}
IP Address: {pending_login.get('ip_address', 'Unknown')}

To APPROVE this login, visit: {approve_url}
To DENY this login, visit: {deny_url}

Or verify by clicking one of these numbers (match it with the number on your screen):
{', '.join([f'{num}: {url}' for num, url in number_urls])}

This link expires in 10 minutes.

If you didn't request this, click the deny link immediately.

- CanteenOs Team
'''
    
    try:
        return send_email_notification(
            to_email=user['email'],
            subject="🔐 Login Verification Required - CanteenOs",
            text_body=text_body,
            html_body=html_body
        )
    except Exception as e:
        print(f"2FA Email error: {e}")
        return False

def create_pending_login(user, organization_id_str, remember_device=False):
    """Create a pending 2FA login request."""
    token = generate_2fa_token()
    numbers, correct_number = generate_2fa_numbers()
    
    pending_model = PendingLoginModel(
        username=user['username'],
        email=user.get('email', ''),
        organization_id=organization_id_str,
        token=token,
        correct_number=correct_number,
        status='pending',
        remember_device=remember_device,
        created_at=datetime.now(),
        expires_at=datetime.now() + timedelta(minutes=10),
        ip_address=request.remote_addr or 'Unknown',
        user_agent=request.user_agent.string[:200] if request.user_agent else 'Unknown'
    )
    
    sql_db.session.add(pending_model)
    sql_db.session.commit()
    
    # Return dict for email template (needs 'numbers' list which isn't stored in DB)
    pending_dict = pending_model.to_dict()
    pending_dict['numbers'] = numbers
    return pending_dict

def cleanup_expired_logins():
    """Remove expired pending logins."""
    PendingLoginModel.query.filter(PendingLoginModel.expires_at < datetime.now()).delete()
    sql_db.session.commit()

# ==================== VALIDATION HELPERS ====================

def validate_email(email):
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format (basic check)."""
    # Accept 10-15 digits, optionally with + prefix and spaces/dashes
    pattern = r'^[\+]?[0-9\s\-]{10,15}$'
    return re.match(pattern, phone.replace(' ', '').replace('-', '')) is not None

def validate_password(password):
    """Validate password strength (length 8+, uppercase, lowercase, number, special char)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character."
    return True, ""

# ==================== HELPER FUNCTIONS ====================

def get_user_by_username(uname):
    """Get user from Neon SQL only (all users are in SQL)."""
    if not uname:
        return None
    user = UserModel.query.filter_by(username=uname).first()
    if user:
        return user.to_dict()
    return None

def get_logged_in_user():
    """Get the currently logged-in user from the session using Neon SQL."""
    if 'username' in session:
        return get_user_by_username(session['username'])
    return None

def get_pending_cart_count():
    """Get the count of pending orders for the logged-in user."""
    if 'username' in session:
        return OrderModel.query.filter_by(
            username=session['username'],
            status='pending'
        ).count()
    return 0

def login_required(f):
    """Decorator to require login for routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require org admin or core admin access for routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_in_user()
        if not user:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Allow core admin or org admin
        if not (user.get('role') == 'core_admin' or user.get('role') == 'org_admin' or user.get('is_admin')):
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def core_admin_required(f):
    """Decorator to require core admin access for routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_in_user()
        if not user or user.get('role') != 'core_admin':
            flash('Core Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_org_admin_code():
    """Generate a unique organization admin code like ORG-A1B2C3."""
    while True:
        code = 'ORG-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Check against SQL organizations (source of truth)
        if not OrganizationModel.query.filter_by(admin_code=code).first():
            return code

def get_user_organization(user):
    """Get the organization object for a user (legacy, checks user's org field)."""
    if user and user.get('organization_id'):
        org_obj = OrganizationModel.query.filter_by(mongo_id=str(user['organization_id'])).first()
        if org_obj:
            return org_obj.to_dict()
    return None

def get_active_organization():
    """Get the currently active organization from session."""
    if 'active_organization_id' in session and session['active_organization_id']:
        try:
            org_obj = OrganizationModel.query.filter_by(mongo_id=str(session['active_organization_id'])).first()
            if org_obj:
                return org_obj.to_dict()
        except:
            pass
    return None

def get_active_organization_id():
    """Get the currently active organization ID from session."""
    if 'active_organization_id' in session and session['active_organization_id']:
        try:
            return ObjectId(session['active_organization_id'])
        except:
            pass
    return None

def get_all_organizations():
    """Get all active organizations for dropdowns from Neon SQL."""
    orgs = OrganizationModel.query.filter_by(is_active=True).order_by(OrganizationModel.name.asc()).all()
    return [org.to_dict() for org in orgs]



# Context processor to make cart_count and organization available in all templates
@app.context_processor
def inject_global_vars():
    user = get_logged_in_user()
    # Use active org from session (selected at login)
    org = get_active_organization() if user else None
    return dict(
        cart_count=get_pending_cart_count(),
        current_org=org,
        is_core_admin=user.get('role') == 'core_admin' if user else False,
        user_avatar=user.get('avatar', 'dosa') if user else 'dosa'
    )

# ==================== SCHEMA MIGRATION ====================

def migrate_schema():
    """Safely add new columns to existing Neon tables without dropping data."""
    with app.app_context():
        try:
            with sql_db.engine.connect() as conn:
                # Add avatar column to users table if missing
                conn.execute(sql_db.text(
                    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar VARCHAR(50) DEFAULT 'dosa'"
                ))
                # Add operating_hours_json column to organizations table if missing
                conn.execute(sql_db.text(
                    "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS operating_hours_json TEXT"
                ))
                # Add pending_logins new columns
                conn.execute(sql_db.text(
                    "ALTER TABLE pending_logins ADD COLUMN IF NOT EXISTS organization_id VARCHAR(24)"
                ))
                conn.execute(sql_db.text(
                    "ALTER TABLE pending_logins ADD COLUMN IF NOT EXISTS remember_device BOOLEAN DEFAULT FALSE"
                ))
                conn.execute(sql_db.text(
                    "ALTER TABLE pending_logins ADD COLUMN IF NOT EXISTS user_agent TEXT"
                ))
                conn.commit()
            print("✅ Schema migration complete (new columns added if missing)")
        except Exception as e:
            print(f"⚠️  Schema migration warning: {e}")

migrate_schema()

# ==================== SEED CORE ADMIN ====================

def seed_core_admin():
    """Create or update Core Admin account from environment variables in Neon SQL."""
    with app.app_context():
        existing = UserModel.query.filter_by(email=CORE_ADMIN_EMAIL).first()
        if not existing:
            new_admin = UserModel(
                first_name='Core',
                last_name='Admin',
                username=CORE_ADMIN_USERNAME,
                password=generate_password_hash(CORE_ADMIN_PASSWORD),
                email=CORE_ADMIN_EMAIL,
                phone='0000000000',
                role='core_admin',
                is_admin=True,
                organization_id=None,
                created_at=datetime.now()
            )
            sql_db.session.add(new_admin)
            sql_db.session.commit()
            print(f"✅ Core Admin account created in SQL (username: {CORE_ADMIN_USERNAME})")
        else:
            # Always update Core Admin to match environment variables
            existing.role = 'core_admin'
            existing.is_admin = True
            existing.username = CORE_ADMIN_USERNAME
            existing.password = generate_password_hash(CORE_ADMIN_PASSWORD)
            sql_db.session.commit()
            print("✅ Core Admin credentials synced from environment in SQL")

# Seed Core Admin on startup
seed_core_admin()

# ==================== SEED DEFAULT MENU ====================

def seed_default_menu():
    """Seed default menu items if database is empty."""
    with app.app_context():
        if MenuItemModel.query.count() == 0:
            # Using Unsplash source URLs which are reliable and don't block hotlinking
            # Format: https://images.unsplash.com/photo-{id}?w=400&h=300&fit=crop
            default_items = [
                {
                    'name': 'Idli',
                    'description': 'Fluffy steamed rice cakes served with sambar and chutney.',
                    'price': 49,
                    'category': 'breakfast',
                    'image_url': 'https://images.unsplash.com/photo-1589301760014-d929f3979dbc?w=400&h=300&fit=crop',
                    'customization_hint': 'Extra chutney, no sambar',
                    'is_available': True,
                    'created_at': datetime.now()
                },
                {
                    'name': 'Masala Dosa',
                    'description': 'Crispy golden crepe filled with spiced potato masala.',
                    'price': 69,
                    'category': 'breakfast',
                    'image_url': 'https://images.unsplash.com/photo-1668236543090-82eba5ee5976?w=400&h=300&fit=crop',
                    'customization_hint': 'Ghee roast, extra crispy',
                    'is_available': True,
                    'created_at': datetime.now()
                },
                {
                    'name': 'Pongal',
                    'description': 'Creamy rice and lentil dish seasoned with pepper and ghee.',
                    'price': 59,
                    'category': 'breakfast',
                    'image_url': 'https://images.unsplash.com/photo-1630383249896-424e482df921?w=400&h=300&fit=crop',
                    'customization_hint': 'Extra ghee, less pepper',
                    'is_available': True,
                    'created_at': datetime.now()
                },
                {
                    'name': 'Medu Vada',
                    'description': 'Crispy fried lentil donuts, golden and crunchy.',
                    'price': 39,
                    'category': 'snacks',
                    'image_url': 'https://images.unsplash.com/photo-1626132647523-66f5bf380027?w=400&h=300&fit=crop',
                    'customization_hint': 'Extra crispy',
                    'is_available': True,
                    'created_at': datetime.now()
                },
                {
                    'name': 'Filter Coffee',
                    'description': 'Traditional South Indian coffee with frothy milk.',
                    'price': 25,
                    'category': 'beverages',
                    'image_url': 'https://images.unsplash.com/photo-1509042239860-f550ce710b93?w=400&h=300&fit=crop',
                    'customization_hint': 'Less sugar, extra strong',
                    'is_available': True,
                    'created_at': datetime.now()
                },
                {
                    'name': 'Upma',
                    'description': 'Savory semolina breakfast with vegetables and spices.',
                    'price': 45,
                    'category': 'breakfast',
                    'image_url': 'https://images.unsplash.com/photo-1567337710282-00832b415979?w=400&h=300&fit=crop',
                    'customization_hint': 'More vegetables, less oil',
                    'is_available': True,
                    'created_at': datetime.now()
                }
            ]
            for item in default_items:
                item['track_stock'] = False
                item['stock'] = 0
                item['low_stock_threshold'] = 5
            for item in default_items:
                new_item = MenuItemModel(**item)
                sql_db.session.add(new_item)
            sql_db.session.commit()
            print("✅ Default menu items seeded to PostgreSQL")

# Seed menu on startup
seed_default_menu()

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    """Homepage - redirect based on login status."""
    if UserModel.query.count() == 0:
        flash('No accounts available. Please register.', 'info')
        return redirect(url_for('register'))
    elif 'username' in session:
        return redirect(url_for('menu'))
    else:
        return redirect(url_for('login'))

@app.route('/about')
def about():
    """About Us page."""
    user = get_logged_in_user()
    return render_template(
        'about.html',
        logged_in_user=user['username'] if user else None,
        is_admin=user.get('is_admin', False) if user else False
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with organization selection and 2FA support."""
    # If already logged in, redirect to menu
    if 'username' in session:
        flash('You are already logged in. Logout first to switch organization.', 'info')
        return redirect(url_for('menu'))
    
    organizations = get_all_organizations()
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        organization_id_str = request.form.get('organization_id', '')
        remember_device = request.form.get('remember_device') == 'on'
        
        user_obj = UserModel.query.filter_by(username=username).first()
        user = user_obj.to_dict() if user_obj else None
        
        if user and check_password_hash(user['password'], password):
            # Core admin doesn't need to select organization or 2FA
            if user.get('role') == 'core_admin':
                complete_login(user, None)
                resp = redirect(url_for('core_admin_dashboard'))
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                return resp
            
            # Regular users and org admins need to select an organization
            if organizations and not organization_id_str:
                flash('Please select an organization.', 'warning')
                return render_template('login.html', organizations=organizations)
            
            # Validate organization selection
            if organization_id_str:
                try:
                    selected_org_id = ObjectId(organization_id_str)
                    # Check if user belongs to this organization
                    user_orgs = user.get('organization_ids', [])
                    # Also check legacy single org field
                    if user.get('organization_id'):
                        if user['organization_id'] not in user_orgs:
                            user_orgs.append(user['organization_id'])
                    
                    if selected_org_id not in user_orgs and user.get('organization_id') != selected_org_id:
                        flash('You are not a member of this organization.', 'danger')
                        return render_template('login.html', organizations=organizations)
                    
                    # Validate org is active
                    org_obj = OrganizationModel.query.filter_by(mongo_id=str(selected_org_id), is_active=True).first()
                    org = org_obj.to_dict() if org_obj else None
                    if not org:
                        flash('This organization is not active.', 'danger')
                        return render_template('login.html', organizations=organizations)
                    
                    # Check if 2FA is enabled for user
                    if user.get('two_factor_enabled', False):
                        # Check for trusted device cookie
                        trusted = verify_remember_device_cookie()
                        if trusted and trusted.get('u') == username:
                            # Trusted device - skip 2FA
                            complete_login(user, str(selected_org_id))
                            resp = redirect(url_for('menu'))
                            flash(f'Welcome back, {user["first_name"]}!', 'success')
                            return resp
                        
                        # Create pending login and send 2FA email
                        cleanup_expired_logins()  # Clean up old requests
                        pending = create_pending_login(user, str(selected_org_id), remember_device=remember_device)
                        
                        if send_2fa_email(user, pending):
                            flash('Check your email to verify this login attempt.', 'info')
                            return redirect(url_for('twofa_waiting', token=pending['token']))
                        else:
                            flash('Failed to send verification email. Please try again.', 'danger')
                            return render_template('login.html', organizations=organizations)
                    
                    # No 2FA - Direct Login
                    complete_login(user, str(selected_org_id))
                    resp = redirect(url_for('menu'))
                    if remember_device:
                        resp = set_remember_device_cookie(resp, username, selected_org_id)
                    flash(f'Welcome back, {user["first_name"]}!', 'success')
                    return resp
                except Exception as e:
                    flash('Invalid organization selected.', 'danger')
                    print(f"Login org error: {e}")
                    return render_template('login.html', organizations=organizations)
            else:
                # No organizations in system
                if user.get('two_factor_enabled', False):
                    trusted = verify_remember_device_cookie()
                    if not trusted or trusted.get('u') != username:
                        cleanup_expired_logins()
                        pending = create_pending_login(user, None, remember_device=remember_device)
                        
                        if send_2fa_email(user, pending):
                            flash('Check your email to verify this login attempt.', 'info')
                            return redirect(url_for('twofa_waiting', token=pending['token']))
                        else:
                            flash('Failed to send verification email. Please try again.', 'danger')
                            return render_template('login.html', organizations=organizations)
                
                complete_login(user, None)
                resp = redirect(url_for('menu'))
                if remember_device:
                    resp = set_remember_device_cookie(resp, username, None)
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                return resp
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', organizations=organizations)



@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page with organization support."""
    organizations = get_all_organizations()
    
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        admin_code = request.form.get('admin_code', '').strip().upper()
        organization_id_str = request.form.get('organization_id', '')
        
        # Validation
        errors = []
        
        if not all([first_name, last_name, username, password, email, phone]):
            errors.append('All fields are required.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        is_valid_pw, pw_msg = validate_password(password)
        if not is_valid_pw:
            errors.append(pw_msg)
        
        if not validate_email(email):
            errors.append('Invalid email format.')
        
        if not validate_phone(phone):
            errors.append('Invalid phone number format.')
        
        if UserModel.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        
        if UserModel.query.filter_by(email=email).first():
            errors.append('Email already registered.')
        
        # Determine role and organization based on admin code
        role = 'user'
        organization_id = None
        org_for_admin = None
        
        if admin_code:
            # Check if it's an organization admin code
            org_obj = OrganizationModel.query.filter_by(admin_code=admin_code).first()
            if org_obj:
                org_for_admin = org_obj.to_dict()
                # Check if this organization already has an admin
                existing_admin = UserModel.query.filter_by(role='org_admin', organization_id=str(org_obj.mongo_id)).first()
                if existing_admin:
                    errors.append('This organization already has an admin. Each organization can only have one admin.')
                else:
                    role = 'org_admin'
                    organization_id = ObjectId(org_obj.mongo_id) if org_obj.mongo_id else None
                    organization_id_str = str(org_obj.mongo_id) if org_obj.mongo_id else None
            else:
                errors.append('Invalid admin code.')
        else:
            # Regular user must select an organization
            if not organization_id_str:
                if organizations:
                    errors.append('Please select your organization.')
            else:
                try:
                    organization_id = ObjectId(organization_id_str)
                    org_obj = OrganizationModel.query.filter_by(mongo_id=organization_id_str, is_active=True).first()
                    if not org_obj:
                        errors.append('Invalid organization selected.')
                except:
                    errors.append('Invalid organization selected.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', organizations=organizations)
        
        # Create user
        hashed_pw = generate_password_hash(password)
        is_admin = role == 'org_admin'
        
        try:
            # Generate a new ObjectId for the user since MongoDB originally did this
            new_user_mongo_id = str(ObjectId())
            
            new_user = UserModel(
                mongo_id=new_user_mongo_id,
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=hashed_pw,
                email=email,
                phone=phone,
                role=role,
                is_admin=is_admin,
                organization_id=organization_id_str if organization_id_str else None,
                created_at=datetime.now()
            )
            sql_db.session.add(new_user)
            sql_db.session.commit()
            
            if role == 'org_admin':
                flash(f'Organization Admin account created for {org_for_admin["name"]}! Please log in.', 'success')
            else:
                flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed. Please try again.', 'danger')
            print(f"Registration error: {e}")
    
    return render_template('register.html', organizations=organizations)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request page."""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user_obj = UserModel.query.filter_by(email=email).first()
        user = user_obj.to_dict() if user_obj else None
        
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            try:
                send_email_notification(
                    to_email=email,
                    subject="Password Reset Request - CanteenOs",
                    text_body=f'''Hi {user['first_name']},

You requested to reset your password. Click the link below to reset:

{reset_url}

This link will expire in 1 hour.

If you did not request this, please ignore this email.

- CanteenOs Team
''',
                    html_body=f'''<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 25px; border: 1px solid #e5e7eb;">
<h2 style="color: #1f2937; margin-top: 0;">Password Reset Request</h2>
<p style="color: #4b5563; font-size: 15px;">Hi <strong>{user['first_name']}</strong>,</p>
<p style="color: #4b5563; font-size: 15px;">You requested to reset your password for your CanteenOs account. Click the button below to proceed:</p>
<p style="text-align: center; margin: 30px 0;">
    <a href="{reset_url}" style="background-color: #22c55e; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">Reset Password</a>
</p>
<p style="color: #6b7280; font-size: 13px;">Or copy and paste this link into your browser:<br><a href="{reset_url}" style="color: #2563eb; word-break: break-all;">{reset_url}</a></p>
<p style="color: #9ca3af; font-size: 12px; margin-top: 25px;">This link will expire in 1 hour. If you did not request this, you can safely ignore this email.</p>
<hr style="border: none; border-top: 1px solid #f3f4f6; margin: 20px 0;">
<p style="color: #9ca3af; font-size: 12px; margin-bottom: 0;">- CanteenOs Team</p>
</div>'''
                )
                flash('Password reset link has been sent to your email.', 'info')
            except Exception as e:
                flash(f'Failed to send email: {e}', 'danger')
                print(f"Email error: {e}")
        else:
            # Don't reveal if email exists for security
            flash('If the email exists, a reset link has been sent.', 'info')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset form."""
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid password reset link.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        is_valid_pw, pw_msg = validate_password(new_password)
        if not is_valid_pw:
            flash(pw_msg, 'danger')
            return render_template('reset_password.html', token=token)
        
        hashed_pw = generate_password_hash(new_password)
        updated = False
        
        # Update in UserModel (Neon DB)
        user_obj = UserModel.query.filter_by(email=email).first()
        if user_obj:
            user_obj.password = hashed_pw
            sql_db.session.commit()
            updated = True
        
        if updated:
            return render_template('password_reset_success.html')
        else:
            flash('Failed to update password. Please try again.', 'danger')
    
    return render_template('reset_password.html', token=token)


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.pop('username', None)
    session.pop('active_organization_id', None)
    resp = redirect(url_for('login'))
    flash('You have been logged out.', 'info')
    return resp


# ==================== 2FA ROUTES ====================

@app.route('/2fa/waiting/<token>')
def twofa_waiting(token):
    """Show waiting page while user checks email for 2FA."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending:
        flash('Invalid or expired verification request.', 'danger')
        return redirect(url_for('login'))
    
    if pending.status != 'pending':
        if pending.status == 'approved':
            flash('Login already approved. Please try logging in again.', 'info')
        else:
            flash('Login was denied or has expired.', 'warning')
        return redirect(url_for('login'))
    
    if pending.expires_at < datetime.now():
        pending.status = 'expired'
        sql_db.session.commit()
        flash('Verification request has expired. Please try again.', 'warning')
        return redirect(url_for('login'))
    
    user = get_user_by_username(pending.username)
    
    return render_template('2fa_waiting.html', 
                           pending=pending.to_dict(), 
                           user=user,
                           correct_number=pending.correct_number)

@app.route('/2fa/approve/<token>')
def twofa_approve(token):
    """Handle 2FA approval from email link."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending:
        flash('Invalid or expired verification request.', 'danger')
        return redirect(url_for('login'))
    
    if pending.status != 'pending':
        flash('This verification request has already been processed.', 'warning')
        return redirect(url_for('login'))
    
    if pending.expires_at < datetime.now():
        pending.status = 'expired'
        sql_db.session.commit()
        flash('Verification request has expired.', 'warning')
        return redirect(url_for('login'))
    
    # Approve the login
    pending.status = 'approved'
    sql_db.session.commit()
    
    return render_template('2fa_approved.html')

@app.route('/2fa/deny/<token>')
def twofa_deny(token):
    """Handle 2FA denial from email link."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending:
        flash('Invalid or expired verification request.', 'danger')
        return redirect(url_for('login'))
    
    if pending.status != 'pending':
        flash('This verification request has already been processed.', 'warning')
        return redirect(url_for('login'))
    
    # Deny the login
    pending.status = 'denied'
    sql_db.session.commit()
    
    return render_template('2fa_denied.html')

@app.route('/2fa/verify/<token>/<int:number>')
def twofa_verify_number(token, number):
    """Handle number verification from email link."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending:
        flash('Invalid or expired verification request.', 'danger')
        return redirect(url_for('login'))
    
    if pending.status != 'pending':
        flash('This verification request has already been processed.', 'warning')
        return redirect(url_for('login'))
    
    if pending.expires_at < datetime.now():
        pending.status = 'expired'
        sql_db.session.commit()
        flash('Verification request has expired.', 'warning')
        return redirect(url_for('login'))
    
    # Check if number is correct
    if number == pending.correct_number:
        pending.status = 'approved'
        sql_db.session.commit()
        return render_template('2fa_approved.html')
    else:
        pending.status = 'denied'
        sql_db.session.commit()
        return render_template('2fa_denied.html', wrong_number=True)

@app.route('/2fa/status/<token>')
def twofa_status(token):
    """AJAX endpoint to check 2FA status for polling."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending:
        return {'status': 'expired', 'redirect': url_for('login')}
    
    if pending.expires_at < datetime.now():
        pending.status = 'expired'
        sql_db.session.commit()
        return {'status': 'expired', 'redirect': url_for('login')}
    
    if pending.status == 'approved':
        # Complete the login in session
        user = get_user_by_username(pending.username)
        if user:
            complete_login(user, pending.organization_id)
            # Build redirect URL
            if user.get('role') == 'core_admin':
                redirect_url = url_for('core_admin_dashboard')
            else:
                redirect_url = url_for('menu')
            return {
                'status': 'approved', 
                'redirect': redirect_url,
                'remember_device': pending.remember_device
            }
        return {'status': 'error', 'redirect': url_for('login')}
    
    if pending.status == 'denied':
        return {'status': 'denied', 'redirect': url_for('login')}
    
    # Calculate remaining time
    remaining = (pending.expires_at - datetime.now()).total_seconds()
    return {'status': 'pending', 'remaining': int(remaining)}

@app.route('/2fa/complete/<token>')
def twofa_complete(token):
    """Complete login after 2FA approval (called from waiting page)."""
    pending = PendingLoginModel.query.filter_by(token=token).first()
    
    if not pending or pending.status != 'approved':
        flash('Invalid verification or not yet approved.', 'danger')
        return redirect(url_for('login'))
    
    user = get_user_by_username(pending.username)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    # Complete login
    complete_login(user, pending.organization_id)
    
    # Delete the pending login
    PendingLoginModel.query.filter_by(token=token).delete()
    sql_db.session.commit()
    
    # Redirect based on role
    if user.get('role') == 'core_admin':
        resp = redirect(url_for('core_admin_dashboard'))
    else:
        resp = redirect(url_for('menu'))
    
    # Set remember device cookie if requested
    if pending.remember_device:
        resp = set_remember_device_cookie(resp, user['username'], pending.organization_id)
    
    flash(f'Welcome back, {user["first_name"]}!', 'success')
    return resp

@app.route('/2fa/toggle', methods=['POST'])
@login_required
def twofa_toggle():
    """Toggle 2FA on/off for the current user."""
    if 'username' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401
    
    user_obj = UserModel.query.filter_by(username=session['username']).first()
    if not user_obj:
        return {'success': False, 'error': 'User not found'}, 404
    
    current_state = bool(user_obj.two_factor_enabled)
    new_state = not current_state
    
    user_obj.two_factor_enabled = new_state
    sql_db.session.commit()
    
    # No Mongo sync needed — SQL is the only source of truth for users
    
    
    if new_state:
        flash('Two-Factor Authentication has been enabled.', 'success')
    else:
        flash('Two-Factor Authentication has been disabled.', 'info')
    
    return redirect(url_for('profile'))


# ==================== USER ROUTES ====================

@app.route('/menu')
@login_required
def menu():
    """Display food menu - dynamic from database, scoped by organization."""
    user = get_logged_in_user()
    
    # Build query based on user role
    query = MenuItemModel.query.filter_by(is_available=True)
    
    # Core admin sees all menu items, others see only their active org's items
    active_org_id = get_active_organization_id()
    if user.get('role') != 'core_admin' and active_org_id:
        query = query.filter_by(organization_id=str(active_org_id))
    
    menu_items = [item.to_dict() for item in query.order_by(MenuItemModel.created_at.desc()).all()]
    
    # For Core Admin, create a mapping of organization_id to organization_name
    org_names = {}
    if user.get('role') == 'core_admin':
        # Get all unique org IDs from menu items
        org_ids = set()
        for item in menu_items:
            if item.get('organization_id'):
                org_ids.add(str(item['organization_id']))
        
        # Fetch organization names from SQL (source of truth)
        for org_id_str in org_ids:
            org_obj = OrganizationModel.query.filter_by(mongo_id=org_id_str).first()
            if org_obj:
                org_names[org_id_str] = org_obj.name
    
    return render_template(
        'menu_item.html',
        menu_items=menu_items,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False),
        user_role=user.get('role', 'user'),
        org_names=org_names
    )

@app.route('/order', methods=['POST'])
@login_required
def order():
    """Add item to cart."""
    user = get_logged_in_user()
    
    try:
        product_name = request.form['productName']
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])
        customizations = request.form.get('customizations', '').strip()
        
        if quantity <= 0:
            flash('Quantity must be greater than 0.', 'warning')
            return redirect(url_for('menu'))
            
        # Check stock availability
        active_org_id = get_active_organization_id()
        query = MenuItemModel.query.filter_by(name=product_name)
        if active_org_id:
            query = query.filter_by(organization_id=str(active_org_id))
            
        menu_item = query.first()
        if menu_item and menu_item.track_stock:
            if menu_item.stock < quantity:
                flash(f'Sorry, only {menu_item.stock} left of {product_name}.', 'danger')
                return redirect(url_for('menu'))
        
        total_price = round(quantity * price, 2)
        
        new_order = OrderModel(
            username=user['username'],
            product_name=product_name,
            quantity=quantity,
            price=price,
            total_price=total_price,
            customizations=customizations,
            status='pending',
            organization_id=str(get_active_organization_id()) if get_active_organization_id() else None,
            order_time=datetime.now(),
            payment_type='upfront'
        )
        sql_db.session.add(new_order)
        sql_db.session.commit()
        
        flash(f'Added {product_name} (x{quantity}) to cart - ₹{total_price}', 'success')
    except (ValueError, KeyError) as e:
        flash('Invalid order data.', 'danger')
        print(f"Order error: {e}")
    
    return redirect(url_for('menu'))

@app.route('/remove_order/<order_id>', methods=['POST'])
@login_required
def remove_order(order_id):
    """Remove item from cart."""
    user = get_logged_in_user()
    
    try:
        if len(order_id) == 24:
            order = OrderModel.query.filter_by(mongo_id=order_id, username=user['username'], status='pending').first()
        else:
            order = OrderModel.query.filter_by(id=int(order_id), username=user['username'], status='pending').first()
            
        if order:
            sql_db.session.delete(order)
            sql_db.session.commit()
            deleted_count = 1
        else:
            deleted_count = 0
            
        if deleted_count:
            flash('Item removed from cart.', 'success')
        else:
            flash('Item not found or already processed.', 'warning')
    except Exception as e:
        flash('Failed to remove item.', 'danger')
        print(f"Remove order error: {e}")
    
    return redirect(url_for('checkout'))

@app.route('/checkout')
@login_required
def checkout():
    """View cart/checkout page."""
    user = get_logged_in_user()
    
    pending_orders_query = OrderModel.query.filter_by(
        username=user['username'],
        status='pending'
    ).order_by(OrderModel.order_time.desc()).all()
    pending_orders = [order.to_dict() for order in pending_orders_query]
    
    total_amount = sum(order['total_price'] for order in pending_orders)
    
    # Get operating hours for the user's active organization
    operating_hours = None
    org_id = get_active_organization_id()
    if org_id:
        org_obj = OrganizationModel.query.filter_by(mongo_id=str(org_id)).first()
        if org_obj:
            org_dict = org_obj.to_dict()
            operating_hours = org_dict.get('operating_hours', {
                'start': '08:00',
                'end': '20:00',
                'all_day': False
            })
    
    return render_template(
        'payment.html',
        orders=pending_orders,
        total_amount=round(total_amount, 2),
        operating_hours=operating_hours,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    """Process payment - change pending orders to paid or scheduled."""
    user = get_logged_in_user()
    
    # Get scheduling options from form
    order_type = request.form.get('order_type', 'now')  # 'now' or 'schedule'
    payment_type = request.form.get('payment_type', 'upfront')  # 'upfront' or 'cod'
    scheduled_time_str = request.form.get('scheduled_time', '')
    
    # Get pending orders count first
    pending_count = OrderModel.query.filter_by(
        username=user['username'],
        status='pending'
    ).count()
    
    if pending_count == 0:
        flash('No items in cart to pay for.', 'warning')
        return redirect(url_for('menu'))
    
    # Handle scheduled orders
    scheduled_time = None
    is_scheduled = False
    new_status = 'paid'
    
    if order_type == 'schedule' and scheduled_time_str:
        try:
            scheduled_time = datetime.strptime(scheduled_time_str, '%Y-%m-%dT%H:%M')
            
            # Validate scheduled time is in the future
            if scheduled_time <= datetime.now():
                flash('Scheduled time must be in the future.', 'danger')
                return redirect(url_for('checkout'))
            
            # Validate against organization operating hours
            org_id = get_active_organization_id()
            if org_id:
                org_obj = OrganizationModel.query.filter_by(mongo_id=str(org_id)).first()
                if org_obj:
                    hours = org_obj.to_dict().get('operating_hours', {})
                    if hours and not hours.get('all_day', False):
                        start_hour = int(hours.get('start', '00:00').split(':')[0])
                        end_hour = int(hours.get('end', '23:59').split(':')[0])
                        scheduled_hour = scheduled_time.hour
                        
                        if scheduled_hour < start_hour or scheduled_hour >= end_hour:
                            flash(f'Canteen is open from {hours["start"]} to {hours["end"]}. Please select a valid time.', 'danger')
                            return redirect(url_for('checkout'))
            
            is_scheduled = True
            # Set status based on payment type
            if payment_type == 'cod':
                new_status = 'scheduled_cod'
            else:
                new_status = 'scheduled_prepaid'
        except ValueError:
            flash('Invalid scheduled time format.', 'danger')
            return redirect(url_for('checkout'))
    
    # Update all pending orders
    update_data = {
        'status': new_status,
        'payment_time': datetime.now() if not is_scheduled or payment_type == 'upfront' else None,
        'scheduled_time': scheduled_time,
        'is_scheduled': is_scheduled,
        'payment_type': payment_type
    }
    
    # Decrement stock for tracked items
    pending_orders = OrderModel.query.filter_by(username=user['username'], status='pending').all()
    
    modified_count = 0
    for order in pending_orders:
        query = MenuItemModel.query.filter_by(name=order.product_name)
        if order.organization_id:
            query = query.filter_by(organization_id=str(order.organization_id))
            
        item = query.first()
        if item and item.track_stock:
            item.stock -= order.quantity
            
        order.status = new_status
        order.payment_time = datetime.now() if not is_scheduled or payment_type == 'upfront' else None
        order.scheduled_time = scheduled_time
        order.is_scheduled = is_scheduled
        order.payment_type = payment_type
        
        modified_count += 1
        
    sql_db.session.commit()
    
    if modified_count > 0:
        if is_scheduled:
            scheduled_time_str = scheduled_time.strftime('%B %d, %Y at %I:%M %p')
            if payment_type == 'cod':
                flash(f'Order scheduled for {scheduled_time_str}. Pay on pickup!', 'success')
            else:
                flash(f'Order scheduled for {scheduled_time_str}. Payment received!', 'success')
        else:
            flash('Payment successful! Your order is being processed.', 'success')
        return redirect(url_for('payment_confirmation'))
    else:
        flash('Payment failed. Please try again.', 'danger')
        return redirect(url_for('checkout'))

@app.route('/payment_confirmation')
@login_required
def payment_confirmation():
    """Payment confirmation page."""
    user = get_logged_in_user()
    
    # Get recently paid orders (within last minute)
    recent_paid_query = OrderModel.query.filter_by(
        username=user['username'],
        status='paid'
    ).order_by(OrderModel.payment_time.desc()).limit(20).all()
    
    recent_paid = [order.to_dict() for order in recent_paid_query]
    
    total_amount = sum(order['total_price'] for order in recent_paid)
    
    return render_template(
        'payment_confirmation.html',
        orders=recent_paid,
        total_amount=round(total_amount, 2),
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/order_history')
@login_required
def order_history():
    """View all non-pending orders."""
    user = get_logged_in_user()
    
    # Get all orders except pending (cart items)
    orders_query = OrderModel.query.filter(
        OrderModel.username == user['username'],
        OrderModel.status != 'pending'
    ).order_by(OrderModel.order_time.desc()).all()
    
    orders = [order.to_dict() for order in orders_query]
    
    return render_template(
        'order_history.html',
        orders=orders,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/track_order/<order_id>')
@login_required
def track_order(order_id):
    """Track a specific order."""
    user = get_logged_in_user()
    
    try:
        if len(order_id) == 24:
            order_query = OrderModel.query.filter_by(mongo_id=order_id, username=user['username']).first()
        else:
            order_query = OrderModel.query.filter_by(id=int(order_id), username=user['username']).first()
            
        order = order_query.to_dict() if order_query else None
        
        if not order:
            flash('Order not found.', 'danger')
            return redirect(url_for('order_history'))
        
        return render_template(
            'track_order.html',
            order=order,
            logged_in_user=user['username'],
            is_admin=user.get('is_admin', False)
        )
    except Exception as e:
        flash('Invalid order ID.', 'danger')
        print(f"Track order error: {e}")
        return redirect(url_for('order_history'))

@app.route('/profile')
@login_required
def profile():
    """View user profile."""
    user = get_logged_in_user()
    
    # Get order statistics
    total_orders = OrderModel.query.filter(
        OrderModel.username == user['username'],
        OrderModel.status != 'pending'
    ).count()
    
    completed_orders = OrderModel.query.filter_by(
        username=user['username'],
        status='completed'
    ).count()
    
    # Calculate total amount spent (orders that are paid or completed)
    paid_orders = OrderModel.query.filter(
        OrderModel.username == user['username'],
        OrderModel.status.in_(['paid', 'preparing', 'ready', 'completed'])
    ).all()
    total_spent = sum(order.total_price for order in paid_orders)
    
    # Get user's organizations
    user_org_ids = user.get('organization_ids', [])
    # Also include legacy single org
    if user.get('organization_id') and user['organization_id'] not in user_org_ids:
        user_org_ids.append(user['organization_id'])
    
    user_organizations = []
    for org_id in user_org_ids:
        org_obj = OrganizationModel.query.filter_by(mongo_id=str(org_id)).first()
        if org_obj:
            user_organizations.append(org_obj.to_dict())
    
    # Get organizations user can join (active orgs they're not in, from SQL)
    all_orgs_objs = OrganizationModel.query.filter_by(is_active=True).all()
    available_organizations = [
        o.to_dict() for o in all_orgs_objs
        if str(o.mongo_id) not in [str(x) for x in user_org_ids]
    ]
    
    return render_template(
        'profile.html',
        user=user,
        total_orders=total_orders,
        completed_orders=completed_orders,
        total_spent=round(total_spent, 2),
        user_organizations=user_organizations,
        available_organizations=available_organizations,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/join_organization', methods=['POST'])
@login_required
def join_organization():
    """Allow user to join an additional organization."""
    user = get_logged_in_user()
    organization_id_str = request.form.get('organization_id', '')
    
    if not organization_id_str:
        flash('Please select an organization.', 'warning')
        return redirect(url_for('profile'))
    
    try:
        org_obj = OrganizationModel.query.filter_by(mongo_id=organization_id_str, is_active=True).first()
        org = org_obj.to_dict() if org_obj else None
        
        if not org:
            flash('Organization not found or inactive.', 'danger')
            return redirect(url_for('profile'))
        
        # Get current organization_ids
        user_org_ids = user.get('organization_ids', [])
        if user.get('organization_id') and user['organization_id'] not in user_org_ids:
            user_org_ids.append(user['organization_id'])
        
        org_id = org['_id']
        # Check if already a member
        if org_id in user_org_ids:
            flash(f'You are already a member of {org["name"]}.', 'info')
            return redirect(url_for('profile'))
        
        # Add to organization_ids
        user_org_ids.append(org_id)
        # Update user in Neon SQL
        user_obj = UserModel.query.filter_by(username=user['username']).first()
        if user_obj:
            user_obj.organization_id = organization_id_str # fallback legacy
            # No organization_ids array in SQL model. For this prototype we're moving to single org per user logic 
            # or if we must support multiple, we'd need a mapping table.
            # But the user schema defined in SQL only has `organization_id`. 
            # I will set organization_id.
            sql_db.session.commit()
            
        flash(f'You have joined {org["name"]}! Logout and login to access it.', 'success')
    except Exception as e:
        flash('Failed to join organization.', 'danger')
        print(f"Join org error: {e}")
    
    return redirect(url_for('profile'))

# Available avatar options (Indian food themed)
AVAILABLE_AVATARS = [
    'dosa', 'biryani', 'tandoori', 'idly', 'panipuri', 'thali', 
    'vadai', 'parotta', 'vadapav', 'pavbhaji', 'proteinshake', 'samosa', 'chai'
]

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    """Update user's avatar selection."""
    user = get_logged_in_user()
    avatar = request.form.get('avatar', 'dosa')
    
    # Validate avatar choice
    if avatar not in AVAILABLE_AVATARS:
        avatar = 'dosa'  # Default fallback
    
    user_obj = UserModel.query.filter_by(username=user['username']).first()
    if user_obj:
        user_obj.avatar = avatar
        sql_db.session.commit()
    
    flash('Avatar updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile."""
    user = get_logged_in_user()
    
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        
        # Validation
        errors = []
        
        if not validate_email(email):
            errors.append('Invalid email format.')
        
        if not validate_phone(phone):
            errors.append('Invalid phone number format.')
        
        # Check if email is taken by another user
        existing_user = UserModel.query.filter(
            UserModel.email == email,
            UserModel.username != user['username']
        ).first()
        if existing_user:
            errors.append('Email is already in use by another account.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('edit_profile.html', user=user, logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        # Update user via SQL
        user_obj = UserModel.query.filter_by(username=user['username']).first()
        if user_obj:
            user_obj.first_name = first_name
            user_obj.last_name = last_name
            user_obj.email = email
            user_obj.phone = phone
            sql_db.session.commit()
        
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    
    return render_template(
        'edit_profile.html',
        user=user,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password while logged in."""
    user = get_logged_in_user()
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        is_valid_pw, pw_msg = validate_password(new_password)
        if not is_valid_pw:
            flash(pw_msg, 'danger')
            return render_template('change_password.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        # Update password via SQL
        hashed_pw = generate_password_hash(new_password)
        user_obj = UserModel.query.filter_by(username=user['username']).first()
        if user_obj:
            user_obj.password = hashed_pw
            sql_db.session.commit()
        
        flash('Password changed successfully.', 'success')
        return redirect(url_for('profile'))
    
    return render_template(
        'change_password.html',
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    """Submit feedback."""
    user = get_logged_in_user()
    
    if request.method == 'POST':
        rating = request.form.get('rating')
        comments = request.form.get('comments', '').strip()
        
        if not rating:
            flash('Please select a rating.', 'warning')
            return render_template('feedback.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        try:
            new_feedback = FeedbackModel(
                username=user['username'],
                rating=int(rating),
                comments=comments,
                submitted_at=datetime.now()
            )
            sql_db.session.add(new_feedback)
            sql_db.session.commit()
            
            flash('Thank you for your feedback!', 'success')
            return redirect(url_for('menu'))
        except Exception as e:
            flash('Failed to submit feedback.', 'danger')
            print(f"Feedback error: {e}")
    
    return render_template(
        'feedback.html',
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

# ==================== ADMIN ROUTES ====================

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with overview statistics - scoped by organization."""
    user = get_logged_in_user()
    
    # Core admin should go to core admin dashboard
    if user.get('role') == 'core_admin':
        return redirect(url_for('core_admin_dashboard'))
    
    # Org admin sees only their organization's data
    org_id = user.get('organization_id')
    org_query = {'organization_id': org_id} if org_id else {}
    
    # Statistics scoped by organization
    base_query = OrderModel.query.filter(OrderModel.status != 'pending')
    if org_id:
        base_query = base_query.filter(OrderModel.organization_id == str(org_id))
    
    total_orders = base_query.count()
    paid_orders = base_query.filter(OrderModel.status == 'paid').count()
    preparing_orders = base_query.filter(OrderModel.status == 'preparing').count()
    ready_orders = base_query.filter(OrderModel.status == 'ready').count()
    completed_orders = base_query.filter(OrderModel.status == 'completed').count()
    
    # Users in this organization (from SQL)
    if org_id:
        total_users = UserModel.query.filter_by(organization_id=str(org_id)).count()
    else:
        total_users = UserModel.query.count()
    
    # Calculate revenue for this organization
    revenue_orders_query = base_query.filter(OrderModel.status.in_(['paid', 'preparing', 'ready', 'completed'])).all()
    total_revenue = sum(order.total_price for order in revenue_orders_query)
    
    # Recent orders (last 10) for this organization
    recent_orders_query = base_query.order_by(OrderModel.order_time.desc()).limit(10).all()
    recent_orders = [order.to_dict() for order in recent_orders_query]
    
    # Get organization info
    org = get_user_organization(user)
    
    return render_template(
        'admin_dashboard.html',
        total_orders=total_orders,
        paid_orders=paid_orders,
        preparing_orders=preparing_orders,
        ready_orders=ready_orders,
        completed_orders=completed_orders,
        total_users=total_users,
        total_revenue=round(total_revenue, 2),
        recent_orders=recent_orders,
        logged_in_user=user['username'],
        is_admin=True,
        organization=org
    )

@app.route('/admin_orders')
@admin_required
def admin_orders():
    """Admin order management."""
    user = get_logged_in_user()
    
    # Get filter from query params
    status_filter = request.args.get('status', 'all')
    
    # Build query
    query = OrderModel.query.filter(OrderModel.status != 'pending')
    if status_filter != 'all':
        query = query.filter(OrderModel.status == status_filter)
        
    if user.get('role') != 'core_admin':
        org_id = user.get('organization_id')
        if org_id:
            query = query.filter(OrderModel.organization_id == str(org_id))
    
    orders_query = query.order_by(OrderModel.order_time.desc()).all()
    orders = [order.to_dict() for order in orders_query]
    
    return render_template(
        'admin_orders.html',
        orders=orders,
        current_filter=status_filter,
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/admin/update_order_status/<order_id>/<new_status>', methods=['POST'])
@admin_required
def update_order_status(order_id, new_status):
    """Update order status."""
    valid_statuses = ['paid', 'preparing', 'ready', 'completed']
    
    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin_orders'))
    
    try:
        if len(order_id) == 24:
            order_query = OrderModel.query.filter_by(mongo_id=order_id).first()
        else:
            order_query = OrderModel.query.filter_by(id=int(order_id)).first()
            
        if not order_query:
            flash('Order not found.', 'warning')
            return redirect(url_for('admin_orders'))
        
        # Handle scheduled order transitions
        current_status = order_query.status
        
        # If transitioning scheduled order to preparing, mark as paid first
        if current_status in ['scheduled_prepaid', 'scheduled_cod'] and new_status == 'preparing':
            # For CoD orders, mark payment_time when preparing (they pay at pickup)
            if current_status == 'scheduled_cod':
                order_query.payment_time = None  # Will be set when completed
        
        order_query.status = new_status
        
        # Add completion time if marking as completed
        if new_status == 'completed':
            order_query.completed_time = datetime.now()
            # For CoD orders, set payment time when order is completed
            if order_query.payment_type == 'cod' and not order_query.payment_time:
                order_query.payment_time = datetime.now()
        
        sql_db.session.commit()
        flash(f'Order marked as {new_status}.', 'success')
    except Exception as e:
        flash('Failed to update order.', 'danger')
        print(f"Update order error: {e}")
    
    return redirect(url_for('admin_orders'))

@app.route('/admin_users')
@admin_required
def admin_users():
    """Admin user management."""
    user = get_logged_in_user()
    
    query_filters = []
    if user.get('role') != 'core_admin':
        org_id = user.get('organization_id')
        if org_id:
            query_filters.append(UserModel.organization_id == str(org_id))
            
    users_objs = UserModel.query.filter(*query_filters).order_by(UserModel.created_at.desc()).all()
    all_users = [u.to_dict() for u in users_objs]
    
    return render_template(
        'admin_users.html',
        users=all_users,
        current_user=user['username'],
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/admin/delete_user/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    """Delete a user and their data."""
    current_user = get_logged_in_user()
    
    # Prevent self-deletion
    if username == current_user['username']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        # Delete user
        user_to_delete = UserModel.query.filter_by(username=username).first()
        
        if user_to_delete:
            sql_db.session.delete(user_to_delete)
            sql_db.session.commit()
            
            # Delete user's orders
            OrderModel.query.filter_by(username=username).delete()
            sql_db.session.commit()
            # Delete user's feedback
            FeedbackModel.query.filter_by(username=username).delete()
            sql_db.session.commit()
            
            flash(f'User "{username}" and all associated data deleted.', 'success')
        else:
            flash('User not found.', 'warning')
    except Exception as e:
        flash('Failed to delete user.', 'danger')
        print(f"Delete user error: {e}")
    
    return redirect(url_for('admin_users'))

@app.route('/admin_feedback')
@admin_required
def admin_feedback():
    """Admin feedback view."""
    user = get_logged_in_user()
    
    feedback_objs = FeedbackModel.query.order_by(FeedbackModel.submitted_at.desc()).all()
    all_feedback = [fb.to_dict() for fb in feedback_objs]
    
    # Calculate average rating
    if all_feedback:
        avg_rating = sum(fb['rating'] for fb in all_feedback) / len(all_feedback)
    else:
        avg_rating = 0
    
    return render_template(
        'admin_feedback.html',
        feedback=all_feedback,
        avg_rating=round(avg_rating, 1),
        total_feedback=len(all_feedback),
        logged_in_user=user['username'],
        is_admin=True
    )

# ==================== ADMIN SETTINGS ROUTES ====================

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """Admin settings page for operating hours."""
    user = get_logged_in_user()
    org_id = user.get('organization_id')
    
    if not org_id:
        flash('No organization found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Fetch org from SQL (source of truth)
    org_obj = OrganizationModel.query.filter_by(mongo_id=str(org_id)).first()
    if not org_obj:
        flash('Organization not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    org = org_obj.to_dict()  # includes operating_hours from JSON column
    operating_hours = org.get('operating_hours', {'start': '08:00', 'end': '20:00', 'all_day': False})
    
    return render_template(
        'admin_settings.html',
        organization=org,
        operating_hours=operating_hours,
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/admin/settings/operating_hours', methods=['POST'])
@admin_required
def update_operating_hours():
    """Update organization operating hours — saved to Neon SQL."""
    import json as _json
    user = get_logged_in_user()
    org_id = user.get('organization_id')
    
    if not org_id:
        flash('No organization found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    start_time = request.form.get('start_time', '08:00')
    end_time = request.form.get('end_time', '20:00')
    all_day = request.form.get('all_day') == 'on'
    
    # Validate time format
    try:
        if not all_day:
            datetime.strptime(start_time, '%H:%M')
            datetime.strptime(end_time, '%H:%M')
    except ValueError:
        flash('Invalid time format.', 'danger')
        return redirect(url_for('admin_settings'))
    
    operating_hours = {'start': start_time, 'end': end_time, 'all_day': all_day}
    
    # Save to SQL via operating_hours_json column
    org_obj = OrganizationModel.query.filter_by(mongo_id=str(org_id)).first()
    if org_obj:
        org_obj.operating_hours_json = _json.dumps(operating_hours)
        sql_db.session.commit()
    
    if all_day:
        flash('Operating hours updated: 24/7 availability enabled.', 'success')
    else:
        flash(f'Operating hours updated: {start_time} - {end_time}', 'success')
    
    return redirect(url_for('admin_settings'))

@app.route('/cancel_scheduled_order/<order_id>', methods=['POST'])
@login_required
def cancel_scheduled_order(order_id):
    """Cancel a scheduled order before it's prepared."""
    user = get_logged_in_user()
    
    try:
        if len(order_id) == 24:
            order_query = OrderModel.query.filter_by(mongo_id=order_id, username=user['username']).first()
        else:
            order_query = OrderModel.query.filter_by(id=int(order_id), username=user['username']).first()
            
        if not order_query or order_query.status not in ['scheduled_prepaid', 'scheduled_cod']:
            flash('Order not found or cannot be cancelled.', 'warning')
            return redirect(url_for('order_history'))
            
        # Check if scheduled time hasn't passed and order isn't being prepared
        if order_query.scheduled_time and order_query.scheduled_time <= datetime.now():
            flash('Cannot cancel order after scheduled pickup time.', 'danger')
            return redirect(url_for('order_history'))
            
        payment_type = order_query.payment_type
        order_query.status = 'cancelled'
        sql_db.session.commit()
        
        if payment_type == 'upfront':
            flash('Scheduled order cancelled. Refund will be processed.', 'success')
        else:
            flash('Scheduled order cancelled successfully.', 'success')
            
    except Exception as e:
        flash('Failed to cancel order.', 'danger')
        print(f"Cancel order error: {e}")
    
    return redirect(url_for('order_history'))

# ==================== MENU MANAGEMENT ROUTES ====================

@app.route('/admin/add_food_item', methods=['POST'])
@admin_required
def add_food_item():
    """Add a new food item to the menu. Admin only."""
    try:
        food_name = request.form['food_name'].strip()
        description = request.form['description'].strip()
        price = float(request.form['price'])
        category = request.form.get('category', 'breakfast')
        image_url = request.form.get('image_url', '').strip()
        customization_hint = request.form.get('customization_hint', '').strip()
        track_stock = request.form.get('track_stock') == 'on'
        stock = int(request.form.get('stock', 0)) if track_stock else 0
        low_stock_threshold = int(request.form.get('low_stock_threshold', 5)) if track_stock else 5
        image_source = request.form.get('image_source', 'url')  # 'url' or 'upload'
        
        final_image_url = ''
        
        # Handle image based on source selection
        if image_source == 'upload':
            # Handle file upload
            if 'food_image' in request.files:
                file = request.files['food_image']
                if file and file.filename and allowed_file(file.filename):
                    # Secure the filename
                    filename = secure_filename(file.filename)
                    # Get file content type
                    content_type = file.content_type or 'image/jpeg'
                    # Store in GridFS
                    file_id = fs.put(
                        file.read(),
                        filename=filename,
                        content_type=content_type,
                        food_name=food_name,
                        uploaded_at=datetime.now()
                    )
                    # Create URL to serve the image
                    final_image_url = url_for('serve_food_image', image_id=str(file_id), _external=False)
                elif file and file.filename:
                    flash('Invalid file type. Please upload an image (PNG, JPG, JPEG, GIF, WEBP).', 'danger')
                    return redirect(url_for('admin_dashboard'))
        else:
            # Use provided URL
            final_image_url = image_url
        
        # Validate that we have an image
        if not final_image_url:
            flash('Please provide an image (upload or URL).', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Check if food item already exists in this organization
        user = get_logged_in_user()
        org_id = user.get('organization_id')
        existing_query = MenuItemModel.query.filter_by(name=food_name)
        if org_id:
            existing_query = existing_query.filter_by(organization_id=str(org_id))
        existing = existing_query.first()
        if existing:
            flash(f'Food item "{food_name}" already exists.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Insert the new food item with organization
        new_item = MenuItemModel(
            name=food_name,
            description=description,
            price=price,
            category=category,
            image_url=final_image_url,
            customization_hint=customization_hint,
            track_stock=track_stock,
            stock=stock,
            low_stock_threshold=low_stock_threshold,
            is_available=True,
            organization_id=str(org_id) if org_id else None
        )
        sql_db.session.add(new_item)
        sql_db.session.commit()
        
        flash(f'Food item "{food_name}" added successfully!', 'success')
    except Exception as e:
        flash('Failed to add food item.', 'danger')
        print(f"Add food error: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/manage_menu')
@admin_required
def admin_manage_menu():
    """Admin page to manage all menu items."""
    user = get_logged_in_user()
    
    query = MenuItemModel.query
    if user.get('role') != 'core_admin':
        org_id = user.get('organization_id')
        if org_id:
            query = query.filter_by(organization_id=str(org_id))
            
    # Get all menu items
    menu_items = [item.to_dict() for item in query.order_by(MenuItemModel.created_at.desc()).all()]
    
    return render_template(
        'admin_manage_menu.html',
        menu_items=menu_items,
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/admin/toggle_food_availability/<food_id>', methods=['POST'])
@admin_required
def toggle_food_availability(food_id):
    """Toggle a food item's availability."""
    try:
        item = MenuItemModel.query.get(int(food_id)) if food_id.isdigit() else MenuItemModel.query.filter_by(mongo_id=food_id).first()
        if item:
            item.is_available = not item.is_available
            sql_db.session.commit()
            new_status = item.is_available
            status_text = 'available' if new_status else 'unavailable'
            flash(f'{item.name} is now {status_text}.', 'success')
        else:
            flash('Food item not found.', 'warning')
    except Exception as e:
        flash('Failed to update availability.', 'danger')
        print(f"Toggle availability error: {e}")
    
    return redirect(url_for('admin_manage_menu'))

@app.route('/admin/delete_food/<food_id>', methods=['POST'])
@admin_required
def delete_food_item(food_id):
    """Delete a food item from the menu."""
    try:
        item = MenuItemModel.query.get(int(food_id)) if food_id.isdigit() else MenuItemModel.query.filter_by(mongo_id=food_id).first()
        if item:
            sql_db.session.delete(item)
            sql_db.session.commit()
            flash(f'{item.name} has been deleted.', 'success')
        else:
            flash('Food item not found.', 'warning')
    except Exception as e:
        flash('Failed to delete food item.', 'danger')
        print(f"Delete food error: {e}")
    
    return redirect(url_for('admin_manage_menu'))

@app.route('/admin/edit_food/<food_id>', methods=['POST'])
@admin_required
def edit_food_item(food_id):
    """Edit/modify an existing food item. Admin only."""
    try:
        food_name = request.form['food_name'].strip()
        description = request.form['description'].strip()
        price = float(request.form['price'])
        category = request.form.get('category', 'breakfast')
        image_url = request.form.get('image_url', '').strip()
        customization_hint = request.form.get('customization_hint', '').strip()
        track_stock = request.form.get('track_stock') == 'on'
        stock = int(request.form.get('stock', 0)) if track_stock else 0
        low_stock_threshold = int(request.form.get('low_stock_threshold', 5)) if track_stock else 5
        image_source = request.form.get('image_source', 'keep')  # 'keep', 'url', or 'upload'
        
        # Get current item to get existing image
        current_item = MenuItemModel.query.get(int(food_id)) if food_id.isdigit() else MenuItemModel.query.filter_by(mongo_id=food_id).first()
        if not current_item:
            flash('Food item not found.', 'danger')
            return redirect(url_for('admin_manage_menu'))
        
        final_image_url = current_item.image_url or ''
        
        # Handle image based on source selection
        if image_source == 'upload':
            # Handle new file upload
            if 'food_image' in request.files:
                file = request.files['food_image']
                if file and file.filename and allowed_file(file.filename):
                    # Delete old GridFS image if it exists
                    if final_image_url and '/food_image/' in final_image_url:
                        try:
                            old_image_id = final_image_url.split('/food_image/')[-1]
                            fs.delete(ObjectId(old_image_id))
                        except Exception:
                            pass  # Old image cleanup failed, continue anyway
                    
                    # Secure the filename
                    filename = secure_filename(file.filename)
                    content_type = file.content_type or 'image/jpeg'
                    # Store in GridFS
                    file_id = fs.put(
                        file.read(),
                        filename=filename,
                        content_type=content_type,
                        food_name=food_name,
                        uploaded_at=datetime.now()
                    )
                    final_image_url = url_for('serve_food_image', image_id=str(file_id), _external=False)
                elif file and file.filename:
                    flash('Invalid file type. Please upload an image (PNG, JPG, JPEG, GIF, WEBP).', 'danger')
                    return redirect(url_for('admin_manage_menu'))
        elif image_source == 'url' and image_url:
            # Use new URL
            final_image_url = image_url
        # If image_source == 'keep', we keep the existing final_image_url
        
        # Validate that we have an image
        if not final_image_url:
            flash('Please provide an image.', 'danger')
            return redirect(url_for('admin_manage_menu'))
        
        # Update the food item
        current_item.name = food_name
        current_item.description = description
        current_item.price = price
        current_item.category = category
        current_item.image_url = final_image_url
        current_item.customization_hint = customization_hint
        current_item.track_stock = track_stock
        current_item.stock = stock
        current_item.low_stock_threshold = low_stock_threshold
        
        sql_db.session.commit()
        
        flash(f'"{food_name}" has been updated successfully!', 'success')
    except Exception as e:
        flash('Failed to update food item.', 'danger')
        print(f"Edit food error: {e}")
    
    return redirect(url_for('admin_manage_menu'))


# Route to serve images from GridFS
@app.route('/food_image/<image_id>')
def serve_food_image(image_id):
    """Serve an image stored in GridFS."""
    try:
        # Get the file from GridFS
        file_data = fs.get(ObjectId(image_id))
        # Return the file with correct content type
        response = Response(
            file_data.read(),
            mimetype=file_data.content_type or 'image/jpeg'
        )
        # Add caching headers
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        return response
    except Exception as e:
        print(f"Error serving image: {e}")
        # Return a transparent 1x1 pixel as fallback
        return Response(
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82',
            mimetype='image/png'
        ), 404

@app.route('/api/stock_alerts')
@admin_required
def stock_alerts():
    user = get_logged_in_user()
    if user.get('role') == 'core_admin':
        return {'alerts': []}
        
    org_id = user.get('organization_id')
    if not org_id:
        return {'alerts': []}
        
    # Find items that are tracked, available, and stock is <= threshold
    alerts = []
    items = list(db.menu_items.find({
        'organization_id': org_id,
        'track_stock': True,
        'is_available': True,
        '$expr': {'$lte': ['$stock', '$low_stock_threshold']}
    }))
    
    for item in items:
        alerts.append({
            'id': str(item['_id']),
            'name': item['name'],
            'stock': item.get('stock', 0),
            'threshold': item.get('low_stock_threshold', 5)
        })
        
    return {'alerts': alerts}

# ==================== CORE ADMIN ROUTES ====================

@app.route('/core_admin_dashboard')
@core_admin_required
def core_admin_dashboard():
    """Core Admin dashboard - global overview of all organizations."""
    user = get_logged_in_user()
    
    # Global statistics (users and orgs from SQL, orders from MongoDB)
    total_orgs = OrganizationModel.query.count()
    active_orgs = OrganizationModel.query.filter_by(is_active=True).count()
    total_users = UserModel.query.filter(UserModel.role != 'core_admin').count()
    total_orders = OrderModel.query.filter(OrderModel.status != 'pending').count()
    
    # Calculate total revenue
    all_paid_orders = OrderModel.query.filter(OrderModel.status.in_(['paid', 'preparing', 'ready', 'completed'])).all()
    total_revenue = sum(order.total_price for order in all_paid_orders)
    
    # Get all organizations with their stats (orgs + users from SQL, orders from MongoDB)
    organizations = []
    for org_obj in OrganizationModel.query.order_by(OrganizationModel.created_at.desc()).all():
        org_dict = org_obj.to_dict()
        org_mid = org_dict.get('_id') or org_dict.get('mongo_id') or str(org_obj.mongo_id)
        # Users count from SQL
        org_users = UserModel.query.filter_by(organization_id=str(org_obj.mongo_id)).count()
        # Orders and revenue from SQL
        org_orders = OrderModel.query.filter(
            OrderModel.organization_id == str(org_obj.mongo_id), 
            OrderModel.status != 'pending'
        ).count()
        
        org_revenue_orders = OrderModel.query.filter(
            OrderModel.organization_id == str(org_obj.mongo_id), 
            OrderModel.status.in_(['paid', 'preparing', 'ready', 'completed'])
        ).all()
        
        org_revenue = sum(o.total_price for o in org_revenue_orders)
        
        organizations.append({
            '_id': org_obj.mongo_id,
            'name': org_obj.name,
            'admin_code': org_obj.admin_code,
            'description': org_obj.description or '',
            'is_active': org_obj.is_active,
            'created_at': org_obj.created_at,
            'user_count': org_users,
            'order_count': org_orders,
            'revenue': round(org_revenue, 2)
        })
    
    return render_template(
        'core_admin_dashboard.html',
        total_organizations=total_orgs,
        active_orgs=active_orgs,
        total_users=total_users,
        total_orders=total_orders,
        total_revenue=round(total_revenue, 2),
        organizations=organizations,
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/core_admin/organizations', methods=['GET', 'POST'])
@core_admin_required
def core_admin_organizations():
    """Manage all organizations - create, view, toggle, delete."""
    user = get_logged_in_user()
    
    if request.method == 'POST':
        # Create new organization
        org_name = request.form.get('org_name', '').strip()
        org_description = request.form.get('org_description', '').strip()
        
        if not org_name:
            flash('Organization name is required.', 'danger')
        elif OrganizationModel.query.filter(OrganizationModel.name.ilike(org_name)).first():
            flash('Organization with this name already exists.', 'danger')
        else:
            # Generate unique admin code
            admin_code = generate_org_admin_code()
            
            new_org = OrganizationModel(
                mongo_id=str(ObjectId()), # Give it a mongo ID string
                name=org_name,
                description=org_description or f'{org_name} Canteen',
                admin_code=admin_code,
                is_active=True,
                created_at=datetime.now()
            )
            sql_db.session.add(new_org)
            sql_db.session.commit()
            
            flash(f'Organization "{org_name}" created! Admin Code: {admin_code}', 'success')
        
        return redirect(url_for('core_admin_organizations'))
    
    # Get all organizations
    org_objs = OrganizationModel.query.order_by(OrganizationModel.created_at.desc()).all()
    organizations = []
    for o in org_objs:
        org_dict = o.to_dict()
        org_dict['user_count'] = UserModel.query.filter_by(organization_id=str(o.mongo_id)).count()
        org_dict['admin_count'] = UserModel.query.filter_by(organization_id=str(o.mongo_id), role='org_admin').count()
        organizations.append(org_dict)
    
    return render_template(
        'core_admin_organizations.html',
        organizations=organizations,
        logged_in_user=user['username'],
        is_admin=True
    )

@app.route('/core_admin/toggle_org/<org_id>', methods=['POST'])
@core_admin_required
def toggle_organization(org_id):
    """Toggle organization active/inactive status."""
    try:
        org_obj = OrganizationModel.query.filter_by(mongo_id=org_id).first()
        if org_obj:
            new_status = not org_obj.is_active
            org_obj.is_active = new_status
            sql_db.session.commit()
            
            status_text = 'activated' if new_status else 'deactivated'
            flash(f'Organization "{org_obj.name}" has been {status_text}.', 'success')
        else:
            flash('Organization not found.', 'danger')
    except Exception as e:
        flash('Failed to update organization.', 'danger')
        print(f"Toggle org error: {e}")
    
    return redirect(url_for('core_admin_organizations'))

@app.route('/core_admin/delete_org/<org_id>', methods=['POST'])
@core_admin_required
def delete_organization(org_id):
    """Delete an organization and all its data."""
    try:
        org_obj = OrganizationModel.query.filter_by(mongo_id=org_id).first()
        if org_obj:
            # Delete all users in this organization from SQL
            UserModel.query.filter_by(organization_id=org_id).delete()
            sql_db.session.commit()
            
            # Delete all orders and menu items from SQL
            OrderModel.query.filter_by(organization_id=str(org_id)).delete()
            MenuItemModel.query.filter_by(organization_id=str(org_id)).delete()
            
            # Delete the organization from SQL
            sql_db.session.delete(org_obj)
            sql_db.session.commit()
            
            flash(f'Organization "{org_obj.name}" and all its data have been deleted.', 'success')
        else:
            flash('Organization not found.', 'danger')
    except Exception as e:
        flash('Failed to delete organization.', 'danger')
        print(f"Delete org error: {e}")
    
    return redirect(url_for('core_admin_organizations'))

@app.route('/core_admin/regenerate_code/<org_id>', methods=['POST'])
@core_admin_required
def regenerate_org_code(org_id):
    """Regenerate admin code for an organization."""
    try:
        org_obj = OrganizationModel.query.filter_by(mongo_id=org_id).first()
        if org_obj:
            new_code = generate_org_admin_code()
            org_obj.admin_code = new_code
            sql_db.session.commit()
            flash(f'New admin code for "{org_obj.name}": {new_code}', 'success')
        else:
            flash('Organization not found.', 'warning')
    except Exception as e:
        flash('Failed to regenerate code.', 'danger')
        print(f"Regenerate code error: {e}")
    
    return redirect(url_for('core_admin_organizations'))

@app.route('/core_admin/delete_user/<username>', methods=['POST'])
@core_admin_required
def core_admin_delete_user(username):
    """Delete any user (Core Admin only)."""
    current_user = get_logged_in_user()
    
    if username == current_user['username']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('core_admin_all_users'))
    
    try:
        user_to_delete = UserModel.query.filter_by(username=username).first()
        if user_to_delete and user_to_delete.role == 'core_admin':
            flash('Cannot delete Core Admin accounts.', 'danger')
            return redirect(url_for('core_admin_all_users'))
        
        if user_to_delete:
            sql_db.session.delete(user_to_delete)
            sql_db.session.commit()
            
            OrderModel.query.filter_by(username=username).delete()
            FeedbackModel.query.filter_by(username=username).delete()
            sql_db.session.commit()
            flash(f'User "{username}" and all associated data deleted.', 'success')
        else:
            flash('User not found.', 'warning')
    except Exception as e:
        flash('Failed to delete user.', 'danger')
        print(f"Delete user error: {e}")
    
    return redirect(url_for('core_admin_all_users'))

@app.route('/core_admin/all_users')
@core_admin_required
def core_admin_all_users():
    """View all users across all organizations."""
    user = get_logged_in_user()
    
    # Get filter parameters
    org_filter = request.args.get('org', '')
    role_filter = request.args.get('role', '')
    
    # Build query
    query_filters = [UserModel.role != 'core_admin']  # Exclude core admin from list
    
    if org_filter:
        query_filters.append(UserModel.organization_id == org_filter)
    
    if role_filter:
        query_filters.append(UserModel.role == role_filter)
    
    # Get users
    users_objs = UserModel.query.filter(*query_filters).order_by(UserModel.created_at.desc()).all()
    all_users = []
    
    # Attach organization names (use raw SQL string org_id to avoid ObjectId type errors)
    for u_obj in users_objs:
        u_dict = u_obj.to_dict()
        raw_org_id = u_obj.organization_id  # plain string from SQL column
        if raw_org_id:
            org_obj = OrganizationModel.query.filter_by(mongo_id=raw_org_id).first()
            u_dict['org_name'] = org_obj.name if org_obj else 'Unknown'
        else:
            u_dict['org_name'] = 'No Organization'
        all_users.append(u_dict)
    
    # Get all organizations for filter dropdown
    org_objs = OrganizationModel.query.order_by(OrganizationModel.name.asc()).all()
    organizations = [o.to_dict() for o in org_objs]
    
    return render_template(
        'core_admin_users.html',
        users=all_users,
        organizations=organizations,
        selected_org=org_filter,
        selected_role=role_filter,
        logged_in_user=user['username'],
        is_admin=True
    )

# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)

