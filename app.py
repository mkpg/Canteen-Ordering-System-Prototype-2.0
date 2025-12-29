"""
Automated Canteen Ordering System
Flask Backend with MongoDB
"""

import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
app.secret_key = os.getenv('SECRET_KEY', 'mongodb+srv://manikandaprabuvk_db_user:<db_password>@cluster0.zyypgsb.mongodb.net/?appName=Cluster0')
ADMIN_CODE = os.getenv('ADMIN_CODE', '2000')

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['canteen_app']
users_col = db['users']
feedback_col = db['feedback']
orders_col = db['orders']

# Create indexes for better performance
users_col.create_index('username', unique=True)
users_col.create_index('email', unique=True)
orders_col.create_index('username')
orders_col.create_index('status')

# Flask-Mail Configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'canteenpros@gmail.com'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'jkhy djbj pnfv pvnn')
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
                "Password Reset Request - MyCanteenApp",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email],
                body=f'''Hi {user['first_name']},

You requested to reset your password. Click the link below to reset:

{reset_url}

This link will expire in 1 hour.

If you did not request this, please ignore this email.

- MyCanteenApp Team
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
    """Display food menu."""
    user = get_logged_in_user()
    return render_template(
        'menu_item.html',
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

# ==================== MAIN ====================

if __name__ == '__main__':
    app.run(debug=True)
