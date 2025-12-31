"""
Automated Canteen Ordering System
Flask Backend with MongoDB
Production-Ready Version
"""

import os
import re
import certifi
import base64
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from gridfs import GridFS
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
from dotenv import load_dotenv
from io import BytesIO

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ==================== SECURE CONFIGURATION ====================
# All sensitive data MUST be in environment variables
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())
ADMIN_CODE = os.getenv('ADMIN_CODE', '2000')

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# MongoDB setup with SSL certificate for Atlas
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['canteen_app']
users_col = db['users']
feedback_col = db['feedback']
orders_col = db['orders']

# GridFS for storing uploaded images in MongoDB
fs = GridFS(db, collection='food_images')

# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    """Check if filename has an allowed image extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create indexes for better performance
users_col.create_index('username', unique=True)
users_col.create_index('email', unique=True)
orders_col.create_index('username')
orders_col.create_index('status')
db.menu_items.create_index('category')
db.menu_items.create_index('is_available')

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
    """Decorator to require admin access for routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_logged_in_user()
        if not user or not user.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor to make cart_count available in all templates
@app.context_processor
def inject_cart_count():
    return dict(cart_count=get_pending_cart_count())

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = users_col.find_one({'username': username})
        
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash(f'Welcome back, {user["first_name"]}!', 'success')
            return redirect(url_for('menu'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        admin_code = request.form.get('admin_code', '').strip()
        
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
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        # Create user
        is_admin = admin_code == ADMIN_CODE
        hashed_pw = generate_password_hash(password)
        
        try:
            users_col.insert_one({
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'password': hashed_pw,
                'email': email,
                'phone': phone,
                'is_admin': is_admin,
                'created_at': datetime.now()
            })
            
            if is_admin:
                flash('Admin account created successfully! Please log in.', 'success')
            else:
                flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed. Please try again.', 'danger')
            print(f"Registration error: {e}")
    
    return render_template('register.html')

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
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ==================== USER ROUTES ====================

@app.route('/menu')
@login_required
def menu():
    """Display food menu - dynamic from database."""
    user = get_logged_in_user()
    
    # Get all available menu items from database
    menu_items = list(db.menu_items.find({'is_available': True}).sort('created_at', -1))
    
    return render_template(
        'menu_item.html',
        menu_items=menu_items,
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
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
            'order_time': datetime.now(),
            'payment_time': None,
            'completed_time': None
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
    
    return render_template(
        'payment.html',
        orders=pending_orders,
        total_amount=round(total_amount, 2),
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    """Process payment - change pending orders to paid."""
    user = get_logged_in_user()
    
    # Get pending orders count first
    pending_count = orders_col.count_documents({
        'username': user['username'],
        'status': 'pending'
    })
    
    if pending_count == 0:
        flash('No items in cart to pay for.', 'warning')
        return redirect(url_for('menu'))
    
    # Update all pending orders to paid
    result = orders_col.update_many(
        {'username': user['username'], 'status': 'pending'},
        {'$set': {'status': 'paid', 'payment_time': datetime.now()}}
    )
    
    if result.modified_count > 0:
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
    
    return render_template(
        'profile.html',
        user=user,
        total_orders=total_orders,
        completed_orders=completed_orders,
        total_spent=round(total_spent, 2),
        logged_in_user=user['username'],
        is_admin=user.get('is_admin', False)
    )

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
    """Admin dashboard with overview statistics."""
    user = get_logged_in_user()
    
    # Statistics
    total_orders = orders_col.count_documents({'status': {'$ne': 'pending'}})
    paid_orders = orders_col.count_documents({'status': 'paid'})
    preparing_orders = orders_col.count_documents({'status': 'preparing'})
    ready_orders = orders_col.count_documents({'status': 'ready'})
    completed_orders = orders_col.count_documents({'status': 'completed'})
    total_users = users_col.count_documents({})
    
    # Calculate revenue
    revenue_orders = list(orders_col.find({
        'status': {'$in': ['paid', 'preparing', 'ready', 'completed']}
    }))
    total_revenue = sum(order['total_price'] for order in revenue_orders)
    
    # Recent orders (last 10)
    recent_orders = list(orders_col.find({
        'status': {'$ne': 'pending'}
    }).sort('order_time', -1).limit(10))
    
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
        is_admin=True
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
    valid_statuses = ['preparing', 'ready', 'completed']
    
    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin_orders'))
    
    try:
        update_data = {'status': new_status}
        
        # Add completion time if marking as completed
        if new_status == 'completed':
            update_data['completed_time'] = datetime.now()
        
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
        
        # Check if food item already exists
        existing = db.menu_items.find_one({'name': food_name})
        if existing:
            flash(f'Food item "{food_name}" already exists.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Insert the new food item
        db.menu_items.insert_one({
            'name': food_name,
            'description': description,
            'price': price,
            'category': category,
            'image_url': final_image_url,
            'customization_hint': customization_hint,
            'is_available': True,
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

# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

