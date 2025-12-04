

# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from werkzeug.security import generate_password_hash, check_password_hash
# from pymongo import MongoClient
# from datetime import datetime
# from bson.objectid import ObjectId
# from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
# from flask_mail import Mail, Message

# app = Flask(__name__)
# app.secret_key = 'mongodb+srv://Retr0000:<1234>@cluster0.7bjv4tl.mongodb.net'  # Replace with a strong, random secret key

# # MongoDB setup
# client = MongoClient("mongodb://localhost:27017/")
# db = client['canteen_app']
# users_col = db['users']
# feedback_col = db['feedback']
# orders_col = db['orders']

# # --- Flask-Mail Configuration ---
# app.config.update(
#     MAIL_SERVER='smtp.gmail.com',
#     MAIL_PORT=587,
#     MAIL_USE_TLS=True,
#     MAIL_USERNAME='canteenpros@gmail.com',         # Replace with your Gmail
#     MAIL_PASSWORD='jkhy djbj pnfv pvnn'            # App password for Gmail
# )
# mail = Mail(app)

# # --- Token serializer for generating and validating tokens ---
# serializer = URLSafeTimedSerializer(app.secret_key)

# # ---------- Helpers ----------
# def get_logged_in_user():
#     if 'username' in session:
#         return users_col.find_one({'username': session['username']})
#     return None

# # ---------- Routes ----------
# @app.route('/')
# def index():
#     if users_col.count_documents({}) == 0:
#         flash('No accounts available. Please register.', 'danger')
#         return redirect(url_for('register'))
#     elif 'username' in session:
#         return redirect(url_for('menu'))
#     else:
#         return redirect(url_for('login'))

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = users_col.find_one({'username': username})

#         if user and check_password_hash(user['password'], password):
#             session['username'] = username
#             return redirect(url_for('menu'))
#         else:
#             flash('Invalid credentials, please try again.', 'danger')

#     return render_template('login.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         first_name = request.form['first_name']
#         last_name = request.form['last_name']
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         email = request.form['email']
#         phone = request.form['phone']
#         admin_code = request.form.get('admin_code', '')

#         if password != confirm_password:
#             flash('Passwords do not match.', 'danger')
#             return render_template('register.html')

#         if users_col.find_one({'username': username}):
#             flash('Username already exists.', 'danger')
#             return render_template('register.html')

#         is_admin = admin_code == '2000'
#         hashed_pw = generate_password_hash(password)

#         users_col.insert_one({
#             'first_name': first_name,
#             'last_name': last_name,
#             'username': username,
#             'password': hashed_pw,
#             'email': email,
#             'phone': phone,
#             'is_admin': is_admin
#         })

#         flash('Registration successful! Please log in.', 'success')
#         return redirect(url_for('login'))

#     return render_template('register.html')

# # --- Forgot Password: Step 1 - Enter Email ---
# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form['email'].strip().lower()
#         user = users_col.find_one({'email': email})

#         if user:
#             token = serializer.dumps(email, salt='password-reset-salt')
#             reset_url = url_for('reset_password', token=token, _external=True)

#             subject = "Password Reset Request"
#             sender = app.config['MAIL_USERNAME']
#             recipients = [email]
#             body = f'''Hi {user['first_name']},

# To reset your password, please click the link below:

# {reset_url}

# If you did not request a password reset, please ignore this email.

# Thanks,
# MyCanteenApp Team
# '''
#             try:
#                 msg = Message(subject=subject, sender=sender, recipients=recipients, body=body)
#                 mail.send(msg)
#                 flash('A password reset link has been sent to your email.', 'info')
#             except Exception as e:
#                 flash('Failed to send email. Please try again later.', 'danger')
#                 print(f"Error sending email: {e}")
#         else:
#             flash('Email not found in our system.', 'danger')

#         return redirect(url_for('forgot_password'))

#     return render_template('forgot_password.html')

# # --- Forgot Password: Step 2 - Reset Password ---
# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     try:
#         email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
#     except SignatureExpired:
#         flash('The password reset link has expired.', 'danger')
#         return redirect(url_for('forgot_password'))
#     except BadSignature:
#         flash('Invalid password reset link.', 'danger')
#         return redirect(url_for('forgot_password'))

#     if request.method == 'POST':
#         new_password = request.form['new_password']
#         confirm_password = request.form['confirm_password']

#         if new_password != confirm_password:
#             flash('Passwords do not match.', 'danger')
#             return render_template('reset_password.html', token=token)

#         hashed_pw = generate_password_hash(new_password)
#         result = users_col.update_one({'email': email}, {'$set': {'password': hashed_pw}})

#         if result.modified_count:
#             return render_template('password_reset_success.html')
#         else:
#             flash('Failed to update password. Please try again.', 'danger')

#     return render_template('reset_password.html', token=token)

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))

# @app.route('/menu')
# def menu():
#     user = get_logged_in_user()
#     if user:
#         return render_template('menu_item.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
#     return redirect(url_for('login'))

# @app.route('/order', methods=['POST'])
# def order():
#     user = get_logged_in_user()
#     if user:
#         product_name = request.form['productName']
#         quantity = int(request.form['quantity'])
#         price = float(request.form['price'])
#         customizations = request.form.get('customizations', '')
#         total_price = quantity * price

#         orders_col.insert_one({
#             'username': user['username'],
#             'product_name': product_name,
#             'quantity': quantity,
#             'price': price,
#             'total_price': total_price,
#             'customizations': customizations,
#             'status': 'pending',
#             'order_time': datetime.now(),
#             'completed_time': None
#         })

#         flash(f'Order placed for {product_name} (Quantity: {quantity}, Total: ₹{total_price})', 'success')
#         return redirect(url_for('menu'))

#     return redirect(url_for('login'))

# @app.route('/checkout')
# def checkout():
#     user = get_logged_in_user()
#     if user:
#         user_orders = list(orders_col.find({'username': user['username']}))
#         total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
#         return render_template('payment.html', orders=user_orders, total_amount=total_amount)
#     return redirect(url_for('login'))

# @app.route('/process_payment', methods=['POST'])
# def process_payment():
#     user = get_logged_in_user()
#     if user:
#         flash('Payment successful!', 'success')
#         return redirect(url_for('payment_confirmation'))
#     return redirect(url_for('login'))

# @app.route('/payment_confirmation')
# def payment_confirmation():
#     user = get_logged_in_user()
#     if user:
#         user_orders = list(orders_col.find({'username': user['username']}))
#         total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
#         return render_template('payment_confirmation.html', orders=user_orders, total_amount=total_amount)
#     return redirect(url_for('login'))

# @app.route('/feedback', methods=['GET', 'POST'])
# def feedback():
#     user = get_logged_in_user()
#     if user:
#         if request.method == 'POST':
#             rating = request.form.get('rating')
#             comments = request.form.get('comments')
#             feedback_col.insert_one({
#                 'username': user['username'],
#                 'rating': int(rating) if rating else None,
#                 'comments': comments
#             })
#             flash('Thank you for your feedback!', 'success')
#             return redirect(url_for('menu'))

#         return render_template('feedback.html')
#     return redirect(url_for('login'))

# @app.route('/admin_dashboard')
# def admin_dashboard():
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         all_orders = list(orders_col.find())
#         return render_template('admin_dashboard.html', orders=all_orders)
#     return redirect(url_for('login'))

# @app.route('/admin_dashboard/complete_order/<order_id>')
# def complete_order(order_id):
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         orders_col.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'completed', 'completed_time': datetime.now()}})
#         flash('Order marked as completed.', 'success')
#         return redirect(url_for('admin_dashboard'))
#     return redirect(url_for('login'))

# @app.route('/profile')
# def profile():
#     user = get_logged_in_user()
#     if not user:
#         return redirect(url_for('login'))
#     return render_template('profile.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))


# if __name__ == '__main__':
#     app.run(debug=True)

# ___________________________________________________________________________________________________________________________________________________



# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from werkzeug.security import generate_password_hash, check_password_hash
# from pymongo import MongoClient
# from datetime import datetime
# from bson.objectid import ObjectId
# from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
# from flask_mail import Mail, Message

# app = Flask(__name__)
# app.secret_key = 'mongodb+srv://Retr0000:<1234>@cluster0.7bjv4tl.mongodb.net'  # Replace with a strong, random secret key

# # MongoDB setup
# client = MongoClient("mongodb://localhost:27017/")
# db = client['canteen_app']
# users_col = db['users']
# feedback_col = db['feedback']
# orders_col = db['orders']

# # --- Flask-Mail Configuration ---
# app.config.update(
#     MAIL_SERVER='smtp.gmail.com',
#     MAIL_PORT=587,
#     MAIL_USE_TLS=True,
#     MAIL_USERNAME='canteenpros@gmail.com',         # Replace with your Gmail
#     MAIL_PASSWORD='jkhy djbj pnfv pvnn'            # App password for Gmail
# )
# mail = Mail(app)

# # --- Token serializer for generating and validating tokens ---
# serializer = URLSafeTimedSerializer(app.secret_key)

# # ---------- Helpers ----------
# def get_logged_in_user():
#     if 'username' in session:
#         return users_col.find_one({'username': session['username']})
#     return None

# # ---------- Routes ----------
# @app.route('/')
# def index():
#     if users_col.count_documents({}) == 0:
#         flash('No accounts available. Please register.', 'danger')
#         return redirect(url_for('register'))
#     elif 'username' in session:
#         return redirect(url_for('menu'))
#     else:
#         return redirect(url_for('login'))

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = users_col.find_one({'username': username})

#         if user and check_password_hash(user['password'], password):
#             session['username'] = username
#             return redirect(url_for('menu'))
#         else:
#             flash('Invalid credentials, please try again.', 'danger')

#     return render_template('login.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         first_name = request.form['first_name']
#         last_name = request.form['last_name']
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         email = request.form['email']
#         phone = request.form['phone']
#         admin_code = request.form.get('admin_code', '')

#         if password != confirm_password:
#             flash('Passwords do not match.', 'danger')
#             return render_template('register.html')

#         if users_col.find_one({'username': username}):
#             flash('Username already exists.', 'danger')
#             return render_template('register.html')

#         is_admin = admin_code == '2000'
#         hashed_pw = generate_password_hash(password)

#         users_col.insert_one({
#             'first_name': first_name,
#             'last_name': last_name,
#             'username': username,
#             'password': hashed_pw,
#             'email': email,
#             'phone': phone,
#             'is_admin': is_admin
#         })

#         flash('Registration successful! Please log in.', 'success')
#         return redirect(url_for('login'))

#     return render_template('register.html')

# # --- Forgot Password: Step 1 - Enter Email ---
# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form['email'].strip().lower()
#         user = users_col.find_one({'email': email})

#         if user:
#             token = serializer.dumps(email, salt='password-reset-salt')
#             reset_url = url_for('reset_password', token=token, _external=True)

#             subject = "Password Reset Request"
#             sender = app.config['MAIL_USERNAME']
#             recipients = [email]
#             body = f'''Hi {user['first_name']},

# To reset your password, please click the link below:

# {reset_url}

# If you did not request a password reset, please ignore this email.

# Thanks,
# MyCanteenApp Team
# '''
#             try:
#                 msg = Message(subject=subject, sender=sender, recipients=recipients, body=body)
#                 mail.send(msg)
#                 flash('A password reset link has been sent to your email.', 'info')
#             except Exception as e:
#                 flash('Failed to send email. Please try again later.', 'danger')
#                 print(f"Error sending email: {e}")
#         else:
#             flash('Email not found in our system.', 'danger')

#         return redirect(url_for('forgot_password'))

#     return render_template('forgot_password.html')

# # --- Forgot Password: Step 2 - Reset Password ---
# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     try:
#         email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
#     except SignatureExpired:
#         flash('The password reset link has expired.', 'danger')
#         return redirect(url_for('forgot_password'))
#     except BadSignature:
#         flash('Invalid password reset link.', 'danger')
#         return redirect(url_for('forgot_password'))

#     if request.method == 'POST':
#         new_password = request.form['new_password']
#         confirm_password = request.form['confirm_password']

#         if new_password != confirm_password:
#             flash('Passwords do not match.', 'danger')
#             return render_template('reset_password.html', token=token)

#         hashed_pw = generate_password_hash(new_password)
#         result = users_col.update_one({'email': email}, {'$set': {'password': hashed_pw}})

#         if result.modified_count:
#             return render_template('password_reset_success.html')
#         else:
#             flash('Failed to update password. Please try again.', 'danger')

#     return render_template('reset_password.html', token=token)

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))

# @app.route('/menu')
# def menu():
#     user = get_logged_in_user()
#     if user:
#         return render_template('menu_item.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
#     return redirect(url_for('login'))

# @app.route('/order', methods=['POST'])
# def order():
#     user = get_logged_in_user()
#     if user:
#         product_name = request.form['productName']
#         quantity = int(request.form['quantity'])
#         price = float(request.form['price'])
#         customizations = request.form.get('customizations', '')
#         total_price = quantity * price

#         orders_col.insert_one({
#             'username': user['username'],
#             'product_name': product_name,
#             'quantity': quantity,
#             'price': price,
#             'total_price': total_price,
#             'customizations': customizations,
#             'status': 'pending',
#             'order_time': datetime.now(),
#             'completed_time': None
#         })

#         flash(f'Order placed for {product_name} (Quantity: {quantity}, Total: ₹{total_price})', 'success')
#         return redirect(url_for('menu'))

#     return redirect(url_for('login'))

# @app.route('/checkout')
# def checkout():
#     user = get_logged_in_user()
#     if user:
#         user_orders = list(orders_col.find({'username': user['username']}))
#         total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
#         return render_template('payment.html', orders=user_orders, total_amount=total_amount)
#     return redirect(url_for('login'))

# @app.route('/process_payment', methods=['POST'])
# def process_payment():
#     user = get_logged_in_user()
#     if user:
#         flash('Payment successful!', 'success')
#         return redirect(url_for('payment_confirmation'))
#     return redirect(url_for('login'))

# @app.route('/payment_confirmation')
# def payment_confirmation():
#     user = get_logged_in_user()
#     if user:
#         user_orders = list(orders_col.find({'username': user['username']}))
#         total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
#         return render_template('payment_confirmation.html', orders=user_orders, total_amount=total_amount)
#     return redirect(url_for('login'))

# @app.route('/feedback', methods=['GET', 'POST'])
# def feedback():
#     user = get_logged_in_user()
#     if user:
#         if request.method == 'POST':
#             rating = request.form.get('rating')
#             comments = request.form.get('comments')
#             feedback_col.insert_one({
#                 'username': user['username'],
#                 'rating': int(rating) if rating else None,
#                 'comments': comments
#             })
#             flash('Thank you for your feedback!', 'success')
#             return redirect(url_for('menu'))

#         return render_template('feedback.html')
#     return redirect(url_for('login'))

# @app.route('/admin_dashboard')
# def admin_dashboard():
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         all_orders = list(orders_col.find())
#         return render_template('admin_dashboard.html', orders=all_orders)  # UPDATED TEMPLATE NAME
#     return redirect(url_for('login'))

# @app.route('/admin_dashboard/complete_order/<order_id>', methods=['POST'])  # use POST for actions!
# def complete_order(order_id):
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         orders_col.update_one(
#             {'_id': ObjectId(order_id)},
#             {'$set': {'status': 'completed', 'completed_time': datetime.now()}}
#         )
#         flash('Order marked as completed.', 'success')
#         return redirect(url_for('admin_dashboard'))
#     return redirect(url_for('login'))

# @app.route('/admin_feedback')
# def admin_feedback():
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         all_feedback = list(feedback_col.find())
#         return render_template('admin_feedback.html', feedback=all_feedback)
#     return redirect(url_for('login'))

# @app.route('/edit_profile', methods=['GET', 'POST'])
# def edit_profile():
#     user = get_logged_in_user()
#     if user:
#         if request.method == 'POST':
#             updated_data = {
#                 'first_name': request.form['first_name'],
#                 'last_name': request.form['last_name'],
#                 'email': request.form['email'],
#                 'phone': request.form['phone'],
#             }
#             users_col.update_one({'username': user['username']}, {'$set': updated_data})
#             flash('Profile updated successfully.', 'success')
#             return redirect(url_for('profile'))
#         return render_template('edit_profile.html', user=user)
#     return redirect(url_for('login'))

# @app.route('/order_history')
# def order_history():
#     user = get_logged_in_user()
#     if user:
#         completed_orders = list(orders_col.find({'username': user['username'], 'status': 'completed'}))
#         return render_template('order_history.html', orders=completed_orders)
#     return redirect(url_for('login'))

# @app.route('/admin_users')
# def admin_users():
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         all_users = list(users_col.find())
#         return render_template('admin_users.html', users=all_users)
#     return redirect(url_for('login'))


# @app.route('/profile')
# def profile():
#     user = users_col.find_one({'username': session['username']})
    
#     # Extract the first and last character of hashed password as a "hint"
#     hashed_pw = user.get('password', '')
#     password_hint = hashed_pw[0] + "..." + hashed_pw[-1] if len(hashed_pw) >= 2 else "N/A"

#     return render_template('profile.html',
#                            username=user['username'],
#                            first_name=user['first_name'],
#                            last_name=user['last_name'],
#                            email=user['email'],
#                            phone=user['phone'])
#                         #    password_hint=password_hint)


# if __name__ == '__main__':
#     app.run(debug=True)



# ____________________________________________________________________________________________________________________________________________________


from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'mongodb+srv://Retr0000:<1234>@cluster0.7bjv4tl.mongodb.net'  # Replace with strong secret key

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client['canteen_app']
users_col = db['users']
feedback_col = db['feedback']
orders_col = db['orders']

# Flask-Mail Configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='canteenpros@gmail.com',
    MAIL_PASSWORD='jkhy djbj pnfv pvnn'  # App password
)
mail = Mail(app)

# Token serializer for reset links
serializer = URLSafeTimedSerializer(app.secret_key)

# ---------- Helpers ----------
def get_logged_in_user():
    if 'username' in session:
        return users_col.find_one({'username': session['username']})
    return None

# ---------- Routes ----------
@app.route('/')
def index():
    if users_col.count_documents({}) == 0:
        flash('No accounts available. Please register.', 'danger')
        return redirect(url_for('register'))
    elif 'username' in session:
        return redirect(url_for('menu'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('menu'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        phone = request.form['phone']
        admin_code = request.form.get('admin_code', '')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if users_col.find_one({'username': username}):
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        is_admin = admin_code == '2000'
        hashed_pw = generate_password_hash(password)

        users_col.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'username': username,
            'password': hashed_pw,
            'email': email,
            'phone': phone,
            'is_admin': is_admin
        })

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = users_col.find_one({'email': email})
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email],
                          body=f'''Hi {user['first_name']},

Click below to reset your password:
{reset_url}

Ignore this if you did not request it.

- MyCanteenApp Team
''')
            try:
                mail.send(msg)
                flash('Reset link sent to your email.', 'info')
            except Exception as e:
                flash('Email sending failed.', 'danger')
                print(f"Email error: {e}")
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('Reset link expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        hashed_pw = generate_password_hash(new_password)
        result = users_col.update_one({'email': email}, {'$set': {'password': hashed_pw}})
        if result.modified_count:
            return render_template('password_reset_success.html')
        else:
            flash('Password update failed.', 'danger')

    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/menu')
def menu():
    user = get_logged_in_user()
    if user:
        return render_template('menu_item.html', logged_in_user=user['username'], is_admin=user.get('is_admin', False))
    return redirect(url_for('login'))

@app.route('/order', methods=['POST'])
def order():
    user = get_logged_in_user()
    if user:
        product_name = request.form['productName']
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])
        customizations = request.form.get('customizations', '')
        total_price = quantity * price

        orders_col.insert_one({
            'username': user['username'],
            'product_name': product_name,
            'quantity': quantity,
            'price': price,
            'total_price': total_price,
            'customizations': customizations,
            'status': 'pending',
            'order_time': datetime.now(),
            'completed_time': None
        })

        flash(f'Order placed for {product_name}.', 'success')
        return redirect(url_for('menu'))
    return redirect(url_for('login'))

@app.route('/checkout')
def checkout():
    user = get_logged_in_user()
    if user:
        user_orders = list(orders_col.find({'username': user['username']}))
        total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
        return render_template('payment.html', orders=user_orders, total_amount=total_amount)
    return redirect(url_for('login'))

@app.route('/process_payment', methods=['POST'])
def process_payment():
    user = get_logged_in_user()
    if user:
        flash('Payment successful!', 'success')
        return redirect(url_for('payment_confirmation'))
    return redirect(url_for('login'))

@app.route('/payment_confirmation')
def payment_confirmation():
    user = get_logged_in_user()
    if user:
        user_orders = list(orders_col.find({'username': user['username']}))
        total_amount = sum(order['total_price'] for order in user_orders if order['status'] == 'pending')
        return render_template('payment_confirmation.html', orders=user_orders, total_amount=total_amount)
    return redirect(url_for('login'))

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    user = get_logged_in_user()
    if user:
        if request.method == 'POST':
            rating = request.form.get('rating')
            comments = request.form.get('comments')
            feedback_col.insert_one({
                'username': user['username'],
                'rating': int(rating) if rating else None,
                'comments': comments
            })
            flash('Thank you for your feedback!', 'success')
            return redirect(url_for('menu'))
        return render_template('feedback.html')
    return redirect(url_for('login'))



@app.route('/admin_dashboard')
def admin_dashboard():
    user = get_logged_in_user()
    if user and user.get('is_admin'):
        all_orders = list(orders_col.find())
        all_users = list(users_col.find())
        all_feedbacks = list(feedback_col.find())
        return render_template('admin_dashboard.html',
                               orders=all_orders,
                               users=all_users)
    return redirect(url_for('login'))



# @app.route('/admin_dashboard')
# def admin_dashboard():
#     user = get_logged_in_user()
#     if user and user.get('is_admin'):
#         all_orders = list(orders_col.find())
#         return render_template('admin_dashboard.html', orders=all_orders)
#     return redirect(url_for('login'))

@app.route('/admin_orders')
def admin_orders():  # ✅ FIX: Add this route
    user = get_logged_in_user()
    if user and user.get('is_admin'):
        all_orders = list(orders_col.find())
        return render_template('admin_orders.html', orders=all_orders)
    return redirect(url_for('login'))

@app.route('/admin_dashboard/complete_order/<order_id>', methods=['POST'])
def complete_order(order_id):
    user = get_logged_in_user()
    if user and user.get('is_admin'):
        orders_col.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': 'completed', 'completed_time': datetime.now()}}
        )
        flash('Order marked as completed.', 'success')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/admin_feedback')
def admin_feedback():
    user = get_logged_in_user()
    if user and user.get('is_admin'):
        all_feedback = list(feedback_col.find())
        return render_template('admin_feedback.html', feedback=all_feedback)
    return redirect(url_for('login'))

@app.route('/admin_users')
def admin_users():
    user = get_logged_in_user()
    if user and user.get('is_admin'):
        all_users = list(users_col.find())
        return render_template('admin_users.html', users=all_users)
    return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user = get_logged_in_user()
    if user:
        if request.method == 'POST':
            updated_data = {
                'first_name': request.form['first_name'],
                'last_name': request.form['last_name'],
                'email': request.form['email'],
                'phone': request.form['phone'],
            }
            users_col.update_one({'username': user['username']}, {'$set': updated_data})
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))
        return render_template('edit_profile.html', user=user)
    return redirect(url_for('login'))

@app.route('/order_history')
def order_history():
    user = get_logged_in_user()
    if user:
        completed_orders = list(orders_col.find({'username': user['username'], 'status': 'completed'}))
        return render_template('order_history.html', orders=completed_orders)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    user = users_col.find_one({'username': session['username']})
    hashed_pw = user.get('password', '')
    password_hint = hashed_pw[0] + "..." + hashed_pw[-1] if len(hashed_pw) >= 2 else "N/A"
    return render_template('profile.html',
                           username=user['username'],
                           first_name=user['first_name'],
                           last_name=user['last_name'],
                           email=user['email'],
                           phone=user['phone'])

if __name__ == '__main__':
    app.run(debug=True)
