# 🍴 MyCanteenApp - Automated Canteen Ordering System

A complete web-based canteen ordering system built with Flask and MongoDB, featuring user authentication, menu ordering, payment processing, order tracking, and admin management.

## ✨ Features

### User Features
- 🔐 **Authentication**: Register, login, logout, password reset via email
- 🍽️ **Menu Browsing**: Browse 10+ food items with descriptions and prices
- 🛒 **Cart Management**: Add items to cart with customizations, remove items
- 💳 **Payment**: Checkout and pay for orders
- 📋 **Order Tracking**: Track order status (Paid → Preparing → Ready → Completed)
- 👤 **Profile Management**: View/edit profile, change password
- ⭐ **Feedback**: Submit star ratings and comments

### Admin Features
- 📊 **Dashboard**: View statistics (orders, users, revenue)
- 📦 **Order Management**: Filter and update order statuses
- 👥 **User Management**: View all users, delete accounts
- ⭐ **Feedback View**: See all customer feedback with average rating

## 🛠️ Tech Stack

- **Backend**: Python Flask
- **Database**: MongoDB (PyMongo)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 4
- **Authentication**: Werkzeug password hashing
- **Email**: Flask-Mail for password reset
- **Security**: itsdangerous for token generation

## 📁 Project Structure

```
proto 2.1/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── README.md             # This file
├── static/
│   ├── css/
│   │   └── styles.css    # Custom CSS styles
│   └── a.jpeg            # QR code for payment
└── templates/
    ├── navbar.html       # Navigation bar component
    ├── login.html        # Login page
    ├── register.html     # Registration page
    ├── forgot_password.html
    ├── reset_password.html
    ├── password_reset_success.html
    ├── menu_item.html    # Food menu page
    ├── payment.html      # Cart/checkout page
    ├── payment_confirmation.html
    ├── profile.html      # User profile
    ├── edit_profile.html
    ├── change_password.html
    ├── order_history.html
    ├── track_order.html
    ├── feedback.html
    ├── admin_dashboard.html
    ├── admin_orders.html
    ├── admin_users.html
    ├── admin_feedback.html
    ├── 404.html
    └── 500.html
```

## 🚀 Setup Instructions

### Prerequisites
- Python 3.8+
- MongoDB (local or MongoDB Atlas)

### Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd "proto 2.1"
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   # Copy the example file
   copy .env.example .env
   
   # Edit .env with your settings:
   # - SECRET_KEY: Generate a random secret key
   # - MONGO_URI: Your MongoDB connection string
   # - MAIL_USERNAME: Your Gmail address
   # - MAIL_PASSWORD: Your Gmail app password
   # - ADMIN_CODE: Secret code for admin registration
   ```

5. **Start MongoDB**
   - Local: Start MongoDB service
   - Atlas: Ensure your connection string is correct

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the application**
   - Open your browser and go to: `http://localhost:5000`

## 📧 Email Configuration (Gmail)

To enable password reset emails:

1. Enable 2-Step Verification in your Google Account
2. Generate an App Password:
   - Go to Google Account → Security → App Passwords
   - Create a new app password for "Mail"
3. Use the generated 16-character password in `MAIL_PASSWORD`

## 👤 Creating an Admin Account

1. Go to the registration page
2. Fill in all required fields
3. Enter the admin code (default: `2000`) in the "Admin Code" field
4. Submit the form

## 🔒 Security Features

- Password hashing with Werkzeug
- Session-based authentication
- Time-limited password reset tokens (1 hour)
- Input validation (email, phone, password)
- Admin-only route protection
- User-scoped order access

## 📱 Screenshots

The application features a modern, responsive design with:
- Clean card-based layouts
- Color-coded status badges
- Interactive star ratings
- Visual order timeline
- Flash messages for user feedback

## 🧪 Testing

### Test Scenarios

| Feature | Test Steps |
|---------|------------|
| Registration | Register with valid data, check for success message |
| Login | Login with registered credentials |
| Add to Cart | Select item, set quantity > 0, add to cart |
| Payment | Checkout, pay, verify status changes to "paid" |
| Order Tracking | Check order history, click "Track" to see timeline |
| Admin Orders | Login as admin, update order status |

## 📝 API Routes

### Public Routes
- `GET /` - Redirect to login or menu
- `GET/POST /login` - User login
- `GET/POST /register` - User registration
- `GET/POST /forgot_password` - Password reset request
- `GET/POST /reset_password/<token>` - Password reset form
- `GET /logout` - Logout

### User Routes (Login Required)
- `GET /menu` - Food menu
- `POST /order` - Add to cart
- `POST /remove_order/<order_id>` - Remove from cart
- `GET /checkout` - View cart
- `POST /process_payment` - Pay for orders
- `GET /payment_confirmation` - Order confirmation
- `GET /profile` - View profile
- `GET/POST /edit_profile` - Edit profile
- `GET/POST /change_password` - Change password
- `GET /order_history` - View orders
- `GET /track_order/<order_id>` - Track order
- `GET/POST /feedback` - Submit feedback

### Admin Routes (Admin Only)
- `GET /admin_dashboard` - Dashboard
- `GET /admin_orders` - Manage orders
- `POST /admin/update_order_status/<order_id>/<status>` - Update status
- `GET /admin_users` - View users
- `POST /admin/delete_user/<username>` - Delete user
- `GET /admin_feedback` - View feedback

## 📄 License

This project is for educational purposes.

## 🤝 Contributing

Feel free to submit issues and enhancement requests!
