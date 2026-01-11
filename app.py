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
from flask_mail import Mail, Message
from flask_compress import Compress
from dotenv import load_dotenv
from io import BytesIO

# Load environment variables
load_dotenv()

app = Flask(__name__)
Compress(app)  # Enable gzip compression for all responses

# ==================== SECURE CONFIGURATION ====================
# All sensitive data MUST be in environment variables
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())
ADMIN_CODE = os.getenv('ADMIN_CODE', '2000')
CORE_ADMIN_EMAIL = os.getenv('CORE_ADMIN_EMAIL', 'admin@canteenos.com')
CORE_ADMIN_PASSWORD = os.getenv('CORE_ADMIN_PASSWORD', 'admin123')
CORE_ADMIN_USERNAME = os.getenv('CORE_ADMIN_USERNAME', 'core_admin')

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# MongoDB setup with SSL certificate for Atlas - OPTIMIZED for performance
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(
    MONGO_URI, 
    tlsCAFile=certifi.where(),
    # Connection pooling for better performance
    maxPoolSize=50,
    minPoolSize=5,
    # Reduce timeouts for faster failure detection
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000,
    socketTimeoutMS=20000,
    # Keep connections alive
    maxIdleTimeMS=45000
)
db = client['canteen_app']
users_col = db['users']
feedback_col = db['feedback']
orders_col = db['orders']
organizations_col = db['organizations']

# GridFS for storing uploaded images in MongoDB
fs = GridFS(db, collection='food_images')

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

# Create indexes for better performance
users_col.create_index('username', unique=True)
users_col.create_index('email', unique=True)
orders_col.create_index('username')
orders_col.create_index('status')
orders_col.create_index([('username', 1), ('status', 1)])  # Compound index for user orders
orders_col.create_index([('organization_id', 1), ('status', 1)])  # Org-scoped orders
orders_col.create_index('order_time')  # For sorting
db.menu_items.create_index('category')
db.menu_items.create_index('is_available')
db.menu_items.create_index([('organization_id', 1), ('is_available', 1)])  # Org-scoped menu
organizations_col.create_index('is_active')

# Flask-Mail Configuration (credentials from environment)
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
)
mail = Mail(app)

# Token serializer for reset links
serializer = URLSafeTimedSerializer(app.secret_key)

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
    """Validate password strength (minimum 6 characters)."""
    return len(password) >= 6

# ==================== HELPER FUNCTIONS ====================

def get_logged_in_user():
    """Get the currently logged-in user from the session."""
    if 'username' in session:
        return users_col.find_one({'username': session['username']})
    return None

def get_pending_cart_count():
    """Get the count of pending orders for the logged-in user."""
    if 'username' in session:
        return orders_col.count_documents({
            'username': session['username'],
            'status': 'pending'
        })
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
        # Check if code already exists
        if not organizations_col.find_one({'admin_code': code}):
            return code

def get_user_organization(user):
    """Get the organization object for a user (legacy, checks user's org field)."""
    if user and user.get('organization_id'):
        return organizations_col.find_one({'_id': user['organization_id']})
    return None

def get_active_organization():
    """Get the currently active organization from session."""
    if 'active_organization_id' in session and session['active_organization_id']:
        try:
            return organizations_col.find_one({'_id': ObjectId(session['active_organization_id'])})
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
    """Get all active organizations for dropdowns."""
    return list(organizations_col.find({'is_active': True}).sort('name', 1))



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

# ==================== SEED CORE ADMIN ====================

def seed_core_admin():
    """Create or update Core Admin account from environment variables."""
    existing = users_col.find_one({'email': CORE_ADMIN_EMAIL})
    if not existing:
        users_col.insert_one({
            'first_name': 'Core',
            'last_name': 'Admin',
            'username': CORE_ADMIN_USERNAME,
            'password': generate_password_hash(CORE_ADMIN_PASSWORD),
            'email': CORE_ADMIN_EMAIL,
            'phone': '0000000000',
            'role': 'core_admin',
            'is_admin': True,
            'organization_id': None,  # Core admin doesn't belong to any org
            'created_at': datetime.now()
        })
        print(f"✅ Core Admin account created (username: {CORE_ADMIN_USERNAME})")
    else:
        # Always update Core Admin to match environment variables
        users_col.update_one(
            {'email': CORE_ADMIN_EMAIL},
            {'$set': {
                'role': 'core_admin',
                'is_admin': True,
                'username': CORE_ADMIN_USERNAME,
                'password': generate_password_hash(CORE_ADMIN_PASSWORD)
            }}
        )
        print("✅ Core Admin credentials synced from environment")

# Seed Core Admin on startup
seed_core_admin()

# ==================== SEED DEFAULT MENU ====================

def seed_default_menu():
    """Seed default menu items if database is empty."""
    if db.menu_items.count_documents({}) == 0:
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
        db.menu_items.insert_many(default_items)
        print("✅ Seeded default menu items")

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
    if users_col.count_documents({}) == 0:
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
    """User login page with organization selection."""
    # If already logged in, redirect to menu
    if 'username' in session:
        flash('You are already logged in. Logout first to switch organization.', 'info')
        return redirect(url_for('menu'))
    
    organizations = get_all_organizations()
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        organization_id_str = request.form.get('organization_id', '')
        
        user = users_col.find_one({'username': username})
        
        if user and check_password_hash(user['password'], password):
            # Core admin doesn't need to select organization
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
                    org = organizations_col.find_one({'_id': selected_org_id, 'is_active': True})
                    if not org:
                        flash('This organization is not active.', 'danger')
                        return render_template('login.html', organizations=organizations)
                    
                    # Direct Login
                    complete_login(user, str(selected_org_id))
                    resp = redirect(url_for('menu'))
                    flash(f'Welcome back, {user["first_name"]}!', 'success')
                    return resp
                except Exception as e:
                    flash('Invalid organization selected.', 'danger')
                    print(f"Login org error: {e}")
                    return render_template('login.html', organizations=organizations)
            else:
                # No organizations in system, just log in
                complete_login(user, None)
                resp = redirect(url_for('menu'))
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
        
        if not validate_password(password):
            errors.append('Password must be at least 6 characters.')
        
        if not validate_email(email):
            errors.append('Invalid email format.')
        
        if not validate_phone(phone):
            errors.append('Invalid phone number format.')
        
        if users_col.find_one({'username': username}):
            errors.append('Username already exists.')
        
        if users_col.find_one({'email': email}):
            errors.append('Email already registered.')
        
        # Determine role and organization based on admin code
        role = 'user'
        organization_id = None
        org_for_admin = None
        
        if admin_code:
            # Check if it's an organization admin code
            org_for_admin = organizations_col.find_one({'admin_code': admin_code})
            if org_for_admin:
                # Check if this organization already has an admin
                existing_admin = users_col.find_one({
                    'role': 'org_admin',
                    'organization_id': org_for_admin['_id']
                })
                if existing_admin:
                    errors.append('This organization already has an admin. Each organization can only have one admin.')
                else:
                    role = 'org_admin'
                    organization_id = org_for_admin['_id']
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
                    org = organizations_col.find_one({'_id': organization_id, 'is_active': True})
                    if not org:
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
            users_col.insert_one({
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'password': hashed_pw,
                'email': email,
                'phone': phone,
                'role': role,
                'is_admin': is_admin,
                'organization_id': organization_id,  # Legacy field for backwards compat
                'organization_ids': [organization_id] if organization_id else [],  # New multi-org field
                'created_at': datetime.now()
            })
            
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
        user = users_col.find_one({'email': email})
        
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg = Message(
                "Password Reset Request - CanteenOs",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email],
                body=f'''Hi {user['first_name']},

You requested to reset your password. Click the link below to reset:

{reset_url}

This link will expire in 1 hour.

If you did not request this, please ignore this email.

- CanteenOs Team
'''
            )
            try:
                mail.send(msg)
                flash('Password reset link has been sent to your email.', 'info')
            except Exception as e:
                flash('Failed to send email. Please try again later.', 'danger')
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
        
        if not validate_password(new_password):
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('reset_password.html', token=token)
        
        hashed_pw = generate_password_hash(new_password)
        result = users_col.update_one(
            {'email': email},
            {'$set': {'password': hashed_pw, 'password_updated_at': datetime.now()}}
        )
        
        if result.modified_count:
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


# ==================== USER ROUTES ====================

@app.route('/menu')
@login_required
def menu():
    """Display food menu - dynamic from database, scoped by organization."""
    user = get_logged_in_user()
    
    # Build query based on user role
    query = {'is_available': True}
    
    # Core admin sees all menu items, others see only their active org's items
    active_org_id = get_active_organization_id()
    if user.get('role') != 'core_admin' and active_org_id:
        query['organization_id'] = active_org_id
    
    menu_items = list(db.menu_items.find(query).sort('created_at', -1))
    
    # For Core Admin, create a mapping of organization_id to organization_name
    org_names = {}
    if user.get('role') == 'core_admin':
        # Get all unique org IDs from menu items
        org_ids = set()
        for item in menu_items:
            if item.get('organization_id'):
                org_ids.add(item['organization_id'])
        
        # Fetch organization names
        for org_id in org_ids:
            org = organizations_col.find_one({'_id': org_id})
            if org:
                org_names[str(org_id)] = org['name']
    
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
        
        total_price = round(quantity * price, 2)
        
        orders_col.insert_one({
            'username': user['username'],
            'product_name': product_name,
            'quantity': quantity,
            'price': price,
            'total_price': total_price,
            'customizations': customizations,
            'status': 'pending',
            'organization_id': get_active_organization_id(),
            'order_time': datetime.now(),
            'payment_time': None,
            'completed_time': None,
            'scheduled_time': None,
            'is_scheduled': False,
            'payment_type': 'upfront'
        })
        
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
        result = orders_col.delete_one({
            '_id': ObjectId(order_id),
            'username': user['username'],
            'status': 'pending'
        })
        
        if result.deleted_count:
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
    
    pending_orders = list(orders_col.find({
        'username': user['username'],
        'status': 'pending'
    }).sort('order_time', -1))
    
    total_amount = sum(order['total_price'] for order in pending_orders)
    
    # Get operating hours for the user's active organization
    operating_hours = None
    org_id = get_active_organization_id()
    if org_id:
        org = organizations_col.find_one({'_id': org_id})
        if org:
            operating_hours = org.get('operating_hours', {
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
    pending_count = orders_col.count_documents({
        'username': user['username'],
        'status': 'pending'
    })
    
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
                org = organizations_col.find_one({'_id': org_id})
                if org and org.get('operating_hours'):
                    hours = org['operating_hours']
                    if not hours.get('all_day', False):
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
    
    result = orders_col.update_many(
        {'username': user['username'], 'status': 'pending'},
        {'$set': update_data}
    )
    
    if result.modified_count > 0:
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
    recent_paid = list(orders_col.find({
        'username': user['username'],
        'status': 'paid'
    }).sort('payment_time', -1).limit(20))
    
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
    orders = list(orders_col.find({
        'username': user['username'],
        'status': {'$ne': 'pending'}
    }).sort('order_time', -1))
    
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
        order = orders_col.find_one({
            '_id': ObjectId(order_id),
            'username': user['username']
        })
        
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
    total_orders = orders_col.count_documents({
        'username': user['username'],
        'status': {'$ne': 'pending'}
    })
    
    completed_orders = orders_col.count_documents({
        'username': user['username'],
        'status': 'completed'
    })
    
    # Calculate total amount spent (orders that are paid or completed)
    paid_orders = list(orders_col.find({
        'username': user['username'],
        'status': {'$in': ['paid', 'preparing', 'ready', 'completed']}
    }))
    total_spent = sum(order['total_price'] for order in paid_orders)
    
    # Get user's organizations
    user_org_ids = user.get('organization_ids', [])
    # Also include legacy single org
    if user.get('organization_id') and user['organization_id'] not in user_org_ids:
        user_org_ids.append(user['organization_id'])
    
    user_organizations = []
    for org_id in user_org_ids:
        org = organizations_col.find_one({'_id': org_id})
        if org:
            user_organizations.append(org)
    
    # Get organizations user can join (active orgs they're not in)
    all_orgs = list(organizations_col.find({'is_active': True}))
    available_organizations = [org for org in all_orgs if org['_id'] not in user_org_ids]
    
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
        org_id = ObjectId(organization_id_str)
        org = organizations_col.find_one({'_id': org_id, 'is_active': True})
        
        if not org:
            flash('Organization not found or inactive.', 'danger')
            return redirect(url_for('profile'))
        
        # Get current organization_ids
        user_org_ids = user.get('organization_ids', [])
        if user.get('organization_id') and user['organization_id'] not in user_org_ids:
            user_org_ids.append(user['organization_id'])
        
        # Check if already a member
        if org_id in user_org_ids:
            flash(f'You are already a member of {org["name"]}.', 'info')
            return redirect(url_for('profile'))
        
        # Add to organization_ids
        user_org_ids.append(org_id)
        users_col.update_one(
            {'username': user['username']},
            {'$set': {'organization_ids': user_org_ids}}
        )
        
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
    
    users_col.update_one(
        {'username': user['username']},
        {'$set': {'avatar': avatar}}
    )
    
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
        existing_user = users_col.find_one({'email': email, 'username': {'$ne': user['username']}})
        if existing_user:
            errors.append('Email is already in use by another account.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('edit_profile.html', user=user, logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        # Update user
        users_col.update_one(
            {'username': user['username']},
            {'$set': {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'phone': phone,
                'updated_at': datetime.now()
            }}
        )
        
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
        
        if not validate_password(new_password):
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('change_password.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
        
        # Update password
        hashed_pw = generate_password_hash(new_password)
        users_col.update_one(
            {'username': user['username']},
            {'$set': {'password': hashed_pw, 'password_updated_at': datetime.now()}}
        )
        
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
            feedback_col.insert_one({
                'username': user['username'],
                'rating': int(rating),
                'comments': comments,
                'submitted_at': datetime.now()
            })
            
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
    order_query_base = {'status': {'$ne': 'pending'}}
    if org_id:
        order_query_base['organization_id'] = org_id
    
    total_orders = orders_col.count_documents(order_query_base)
    paid_orders = orders_col.count_documents({**org_query, 'status': 'paid'})
    preparing_orders = orders_col.count_documents({**org_query, 'status': 'preparing'})
    ready_orders = orders_col.count_documents({**org_query, 'status': 'ready'})
    completed_orders = orders_col.count_documents({**org_query, 'status': 'completed'})
    
    # Users in this organization
    user_query = {'organization_id': org_id} if org_id else {}
    total_users = users_col.count_documents(user_query)
    
    # Calculate revenue for this organization
    revenue_query = {'status': {'$in': ['paid', 'preparing', 'ready', 'completed']}}
    if org_id:
        revenue_query['organization_id'] = org_id
    revenue_orders = list(orders_col.find(revenue_query))
    total_revenue = sum(order['total_price'] for order in revenue_orders)
    
    # Recent orders (last 10) for this organization
    recent_query = {'status': {'$ne': 'pending'}}
    if org_id:
        recent_query['organization_id'] = org_id
    recent_orders = list(orders_col.find(recent_query).sort('order_time', -1).limit(10))
    
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
    query = {'status': {'$ne': 'pending'}}
    if status_filter != 'all':
        query['status'] = status_filter
    
    orders = list(orders_col.find(query).sort('order_time', -1))
    
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
        order = orders_col.find_one({'_id': ObjectId(order_id)})
        if not order:
            flash('Order not found.', 'warning')
            return redirect(url_for('admin_orders'))
        
        update_data = {'status': new_status}
        
        # Handle scheduled order transitions
        current_status = order.get('status', '')
        
        # If transitioning scheduled order to preparing, mark as paid first
        if current_status in ['scheduled_prepaid', 'scheduled_cod'] and new_status == 'preparing':
            # For CoD orders, mark payment_time when preparing (they pay at pickup)
            if current_status == 'scheduled_cod':
                update_data['payment_time'] = None  # Will be set when completed
            update_data['status'] = 'preparing'
        
        # Add completion time if marking as completed
        if new_status == 'completed':
            update_data['completed_time'] = datetime.now()
            # For CoD orders, set payment time when order is completed
            if order.get('payment_type') == 'cod' and not order.get('payment_time'):
                update_data['payment_time'] = datetime.now()
        
        result = orders_col.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': update_data}
        )
        
        if result.modified_count:
            flash(f'Order marked as {new_status}.', 'success')
        else:
            flash('Order not found or already in that status.', 'warning')
    except Exception as e:
        flash('Failed to update order.', 'danger')
        print(f"Update order error: {e}")
    
    return redirect(url_for('admin_orders'))

@app.route('/admin_users')
@admin_required
def admin_users():
    """Admin user management."""
    user = get_logged_in_user()
    
    all_users = list(users_col.find().sort('created_at', -1))
    
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
        user_result = users_col.delete_one({'username': username})
        
        if user_result.deleted_count:
            # Delete user's orders
            orders_col.delete_many({'username': username})
            # Delete user's feedback
            feedback_col.delete_many({'username': username})
            
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
    
    all_feedback = list(feedback_col.find().sort('submitted_at', -1))
    
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
    
    org = organizations_col.find_one({'_id': org_id})
    if not org:
        flash('Organization not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get operating hours with defaults
    operating_hours = org.get('operating_hours', {
        'start': '08:00',
        'end': '20:00',
        'all_day': False
    })
    
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
    """Update organization operating hours."""
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
    
    operating_hours = {
        'start': start_time,
        'end': end_time,
        'all_day': all_day
    }
    
    organizations_col.update_one(
        {'_id': org_id},
        {'$set': {'operating_hours': operating_hours}}
    )
    
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
        order = orders_col.find_one({
            '_id': ObjectId(order_id),
            'username': user['username'],
            'status': {'$in': ['scheduled_prepaid', 'scheduled_cod']}
        })
        
        if not order:
            flash('Order not found or cannot be cancelled.', 'warning')
            return redirect(url_for('order_history'))
        
        # Check if scheduled time hasn't passed and order isn't being prepared
        if order.get('scheduled_time') and order['scheduled_time'] <= datetime.now():
            flash('Cannot cancel order after scheduled pickup time.', 'danger')
            return redirect(url_for('order_history'))
        
        # Delete or mark as cancelled
        orders_col.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': 'cancelled', 'cancelled_time': datetime.now()}}
        )
        
        if order.get('payment_type') == 'upfront':
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
        existing_query = {'name': food_name}
        if org_id:
            existing_query['organization_id'] = org_id
        existing = db.menu_items.find_one(existing_query)
        if existing:
            flash(f'Food item "{food_name}" already exists.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Insert the new food item with organization
        db.menu_items.insert_one({
            'name': food_name,
            'description': description,
            'price': price,
            'category': category,
            'image_url': final_image_url,
            'customization_hint': customization_hint,
            'is_available': True,
            'organization_id': org_id,
            'created_at': datetime.now()
        })
        
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
    
    # Get all menu items
    menu_items = list(db.menu_items.find().sort('created_at', -1))
    
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
        item = db.menu_items.find_one({'_id': ObjectId(food_id)})
        if item:
            new_status = not item.get('is_available', True)
            db.menu_items.update_one(
                {'_id': ObjectId(food_id)},
                {'$set': {'is_available': new_status}}
            )
            status_text = 'available' if new_status else 'unavailable'
            flash(f'{item["name"]} is now {status_text}.', 'success')
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
        item = db.menu_items.find_one({'_id': ObjectId(food_id)})
        if item:
            db.menu_items.delete_one({'_id': ObjectId(food_id)})
            flash(f'{item["name"]} has been deleted.', 'success')
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
        image_source = request.form.get('image_source', 'keep')  # 'keep', 'url', or 'upload'
        
        # Get current item to get existing image
        current_item = db.menu_items.find_one({'_id': ObjectId(food_id)})
        if not current_item:
            flash('Food item not found.', 'danger')
            return redirect(url_for('admin_manage_menu'))
        
        final_image_url = current_item.get('image_url', '')
        
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
        result = db.menu_items.update_one(
            {'_id': ObjectId(food_id)},
            {'$set': {
                'name': food_name,
                'description': description,
                'price': price,
                'category': category,
                'image_url': final_image_url,
                'customization_hint': customization_hint,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count:
            flash(f'"{food_name}" has been updated successfully!', 'success')
        else:
            flash('No changes were made.', 'info')
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

# ==================== CORE ADMIN ROUTES ====================

@app.route('/core_admin_dashboard')
@core_admin_required
def core_admin_dashboard():
    """Core Admin dashboard - global overview of all organizations."""
    user = get_logged_in_user()
    
    # Global statistics
    total_orgs = organizations_col.count_documents({})
    active_orgs = organizations_col.count_documents({'is_active': True})
    total_users = users_col.count_documents({'role': {'$ne': 'core_admin'}})
    total_orders = orders_col.count_documents({'status': {'$ne': 'pending'}})
    
    # Calculate total revenue
    all_paid_orders = list(orders_col.find({
        'status': {'$in': ['paid', 'preparing', 'ready', 'completed']}
    }))
    total_revenue = sum(order.get('total_price', 0) for order in all_paid_orders)
    
    # Get all organizations with their stats
    organizations = []
    for org in organizations_col.find().sort('created_at', -1):
        org_id = org['_id']
        org_users = users_col.count_documents({'organization_id': org_id})
        org_orders = orders_col.count_documents({'organization_id': org_id, 'status': {'$ne': 'pending'}})
        org_revenue_orders = list(orders_col.find({
            'organization_id': org_id,
            'status': {'$in': ['paid', 'preparing', 'ready', 'completed']}
        }))
        org_revenue = sum(o.get('total_price', 0) for o in org_revenue_orders)
        
        organizations.append({
            '_id': org_id,
            'name': org['name'],
            'admin_code': org['admin_code'],
            'description': org.get('description', ''),
            'is_active': org.get('is_active', True),
            'created_at': org.get('created_at'),
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
        elif organizations_col.find_one({'name': {'$regex': f'^{org_name}$', '$options': 'i'}}):
            flash('Organization with this name already exists.', 'danger')
        else:
            # Generate unique admin code
            admin_code = generate_org_admin_code()
            
            organizations_col.insert_one({
                'name': org_name,
                'description': org_description or f'{org_name} Canteen',
                'admin_code': admin_code,
                'is_active': True,
                'created_at': datetime.now()
            })
            
            flash(f'Organization "{org_name}" created! Admin Code: {admin_code}', 'success')
        
        return redirect(url_for('core_admin_organizations'))
    
    # Get all organizations
    organizations = list(organizations_col.find().sort('created_at', -1))
    for org in organizations:
        org['user_count'] = users_col.count_documents({'organization_id': org['_id']})
        org['admin_count'] = users_col.count_documents({'organization_id': org['_id'], 'role': 'org_admin'})
    
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
        org = organizations_col.find_one({'_id': ObjectId(org_id)})
        if org:
            new_status = not org.get('is_active', True)
            organizations_col.update_one(
                {'_id': ObjectId(org_id)},
                {'$set': {'is_active': new_status}}
            )
            status_text = 'activated' if new_status else 'deactivated'
            flash(f'Organization "{org["name"]}" has been {status_text}.', 'success')
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
        org = organizations_col.find_one({'_id': ObjectId(org_id)})
        if org:
            org_oid = ObjectId(org_id)
            
            # Delete all users in this organization
            users_col.delete_many({'organization_id': org_oid})
            
            # Delete all orders from this organization
            orders_col.delete_many({'organization_id': org_oid})
            
            # Delete all menu items from this organization
            db.menu_items.delete_many({'organization_id': org_oid})
            
            # Delete the organization
            organizations_col.delete_one({'_id': org_oid})
            
            flash(f'Organization "{org["name"]}" and all its data have been deleted.', 'success')
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
        org = organizations_col.find_one({'_id': ObjectId(org_id)})
        if org:
            new_code = generate_org_admin_code()
            organizations_col.update_one(
                {'_id': ObjectId(org_id)},
                {'$set': {'admin_code': new_code}}
            )
            flash(f'New admin code for "{org["name"]}": {new_code}', 'success')
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
        user_to_delete = users_col.find_one({'username': username})
        if user_to_delete and user_to_delete.get('role') == 'core_admin':
            flash('Cannot delete Core Admin accounts.', 'danger')
            return redirect(url_for('core_admin_all_users'))
        
        user_result = users_col.delete_one({'username': username})
        
        if user_result.deleted_count:
            orders_col.delete_many({'username': username})
            feedback_col.delete_many({'username': username})
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
    query = {'role': {'$ne': 'core_admin'}}  # Exclude core admin from list
    
    if org_filter:
        try:
            query['organization_id'] = ObjectId(org_filter)
        except:
            pass
    
    if role_filter:
        query['role'] = role_filter
    
    # Get users
    all_users = list(users_col.find(query).sort('created_at', -1))
    
    # Attach organization names
    for u in all_users:
        if u.get('organization_id'):
            org = organizations_col.find_one({'_id': u['organization_id']})
            u['org_name'] = org['name'] if org else 'Unknown'
        else:
            u['org_name'] = 'No Organization'
    
    # Get all organizations for filter dropdown
    organizations = list(organizations_col.find().sort('name', 1))
    
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
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

