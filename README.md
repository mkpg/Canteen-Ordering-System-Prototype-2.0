# 🍽️ CanteenOs — Automated Canteen Ordering System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/Neon-PostgreSQL-00e699.svg?logo=postgresql&logoColor=white)](https://neon.tech/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248.svg?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Email](https://img.shields.io/badge/Brevo-REST_API-0B996F.svg?logo=brevo&logoColor=white)](https://www.brevo.com/)
[![Production Ready](https://img.shields.io/badge/Deployment-Render-46E3B7.svg?logo=render&logoColor=white)](https://render.com/)

A modern, cloud-ready web application designed for automated campus and workplace food ordering, real-time kitchen tracking, multi-organization management, and secure administrative controls.

---

## 🌟 Overview

**CanteenOs** modernizes traditional canteen operations into a seamless digital workflow. Built with a robust hybrid-database architecture, it pairs **Neon PostgreSQL** for mission-critical relational data (user authentication and organization hierarchies) with **MongoDB Atlas** for dynamic catalogs, orders, and image asset storage.

Transactional notifications (password resets and 2FA login verification) are powered by **Brevo's REST API over HTTPS**, ensuring 100% reliable email delivery without cloud firewall port blocks.

---

## ✨ Key Features

### 👤 Customer Experience
* **Interactive Menu**: Browse categorized food items, view dynamic availability badges, pricing, and high-resolution food images stored via GridFS.
* **Smart Cart & Customization**: Add menu items with custom preparation notes, real-time pricing calculation, and cart management.
* **Instant Checkout & Tracking**: Fast payment workflows with an intuitive real-time order status timeline (`Paid` → `Preparing` → `Ready` → `Completed`).
* **Profile & History**: Manage personal account information, view previous receipts, and track active orders.
* **Reviews & Ratings**: Submit star ratings and feedback for meals and service.

### 🛡️ Security & Authentication
* **Modern Password Security**: Secure password hashing with Werkzeug and salt-protected time-limited tokens.
* **Cloud-Reliable Email API**: Integrated with Brevo HTTPS REST API to bypass outbound SMTP restrictions on modern cloud platforms (Render, AWS, etc.).
* **Two-Factor Authentication (2FA)**: Email-based approval system featuring instant approve/deny links and challenge-number matching.
* **Secure Sessions & Proxies**: Built-in `ProxyFix` middleware for reverse proxies and HTTPS termination in production.

### 🏢 Multi-Tenant & Organization Controls
* **Organization Scoping**: Support for multiple organizations/campuses with dedicated admin codes and isolated order feeds.
* **Role-Based Access Control**: Strict segregation between Customers, Organization Admins, and Core Platform Superadmins.

### 👨‍🍳 Canteen Management & Analytics
* **Kitchen Order Queue**: Live order pipeline allowing canteen staff to progress orders from received to prepared in real time.
* **Item & Stock Controls**: Instant toggle for item availability, price adjustments, and stock alerts.
* **Feedback Analytics**: Centralized customer feedback dashboard with aggregate satisfaction scores.

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Flask 3.0 | Application routing, sessions, and business logic |
| **Relational Database** | Neon PostgreSQL + SQLAlchemy | User identities, authentication, and organization tenancy |
| **Document Database** | MongoDB Atlas + PyMongo | Dynamic food menus, orders, customer feedback |
| **Asset Storage** | MongoDB GridFS | Persistent storage and streaming of food images |
| **Email Delivery** | Brevo Transactional REST API | Password recovery and 2FA verification over HTTPS |
| **Frontend** | HTML5, Modern CSS, Bootstrap 4, JS | Responsive mobile-first interface |
| **WSGI Server** | Gunicorn 21.2 | High-concurrency production HTTP server |

---

## ⚙️ Environment Configuration

Create a `.env` file in the root directory (based on `.env.example`):

```env
# Flask Security
SECRET_KEY=your-super-secret-production-key

# Database Connections
NEON_DATABASE_URL=postgresql://user:password@ep-xyz.neon.tech/neondb?sslmode=require
MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/canteen_app

# Email Service (Brevo HTTPS API)
BREVO_API_KEY=xkeysib-your-brevo-api-key
MAIL_DEFAULT_SENDER=your-verified-sender@example.com

# Core Administrator Setup
ADMIN_CODE=your_secret_admin_code
CORE_ADMIN_EMAIL=admin@canteen.local
CORE_ADMIN_PASSWORD=your_secure_password
CORE_ADMIN_USERNAME=core_admin
```

---

## 🚀 Quickstart Guide

### 1. Clone & Setup Environment
```bash
git clone https://github.com/your-repo/Canteen-Ordering-System-Prototype-2.0.git
cd Canteen-Ordering-System-Prototype-2.0

# Create and activate a virtual environment
python -m venv .venv

# Windows:
.\.venv\Scripts\activate

# macOS / Linux:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
```
Open your browser and navigate to: **`http://localhost:8080`**

---

## ☁️ Deployment (Render)

This repository is pre-configured for seamless deployment on **Render**:

1. Create a new **Web Service** on Render connected to your repository.
2. Configure the build and start commands:
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `gunicorn app:app`
3. Under the **Environment Variables** tab, add your production values (`SECRET_KEY`, `NEON_DATABASE_URL`, `MONGO_URI`, `BREVO_API_KEY`, `MAIL_DEFAULT_SENDER`, etc.).
4. Deploy! The service will automatically spin up on HTTPS.

---

## 📂 Project Structure

```
Canteen-Ordering-System-Prototype-2.0/
├── app.py                 # Core Flask backend, models, APIs & routes
├── Procfile               # Production WSGI process definition (Gunicorn)
├── render.yaml            # Render infrastructure specification
├── requirements.txt       # Project dependencies
├── .env.example           # Reference environment variables
├── static/
│   ├── css/
│   │   └── styles.css     # Custom theme & component styling
│   └── a.jpeg             # Static payment QR code
└── templates/             # Jinja2 HTML templates
    ├── navbar.html        # Dynamic header & user navigation
    ├── menu_item.html     # Food catalog & cart selection
    ├── payment.html       # Checkout & payment processing
    ├── track_order.html   # Visual real-time order tracker
    ├── admin_*.html       # Administrative dashboards & queues
    └── ...                # Auth, profile, and error templates
```

---

## 📄 License

This project is open-source and intended for educational and institutional dining management prototyping.
