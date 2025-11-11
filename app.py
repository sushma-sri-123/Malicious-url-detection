import os
import sqlite3
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
import joblib
from flask_cors import CORS
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from werkzeug.security import generate_password_hash, check_password_hash
from url_checker import check_url_heuristics

# ============================================
# 🔧 Flask App Setup
# ============================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'supersecretkey123456'
CORS(app)

# ============================================
# 🧩 Database Setup
# ============================================
DB_PATH = os.path.join(BASE_DIR, 'users.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ============================================
# 🤖 Load ML Model
# ============================================
model = joblib.load(os.path.join(BASE_DIR, 'models', 'malicious_url_model.pkl'))
vectorizer = joblib.load(os.path.join(BASE_DIR, 'models', 'tfidf_vectorizer.pkl'))

# ============================================
# 🌐 ROUTES
# ============================================

# --------------------------
# HOME (Landing Page)
# --------------------------
@app.route('/')
def home():
    return render_template("dashboard2.html")

# --------------------------
# SIGNUP PAGE
# --------------------------
@app.route('/signup')
def signup_page():
    return render_template("signup.html")

# --------------------------
# LOGIN PAGE
# --------------------------
@app.route('/login')
def login_page():
    return render_template("login.html")

# --------------------------
# DASHBOARD PAGE
# --------------------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template("dashboard.html", user=session['user'])

# --------------------------
# PROFILE PAGE
# --------------------------
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('profile.html', user=session['user'])

# --------------------------
# SETTINGS PAGE
# --------------------------
@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('settings.html', user=session['user'])

# --------------------------
# HELP PAGE
# --------------------------
@app.route('/help')
def help_page():
    return render_template('help.html')

# --------------------------
# LOGOUT
# --------------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# --------------------------
# FORGOT PASSWORD
# --------------------------
@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

# --------------------------
# SIGNUP API
# --------------------------
@app.route('/api/signup', methods=['POST'])
def signup_api():
    data = request.get_json()
    name, email, password = data.get('name'), data.get('email'), data.get('password')

    if not all([name, email, password]):
        return jsonify({'error': 'All fields are required'}), 400

    hashed_pw = generate_password_hash(password)
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_pw))
        conn.commit()
        return jsonify({'message': 'Signup successful'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        conn.close()

# --------------------------
# LOGIN API
# --------------------------
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email=?', (email,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user'] = dict(user)
        return jsonify({'message': 'Login successful', 'redirect': url_for('dashboard')}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# --------------------------
# UPDATE PROFILE API
# --------------------------
@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not all([user_id, name, email, password]):
        return jsonify({'error': 'All fields are required'}), 400

    hashed_pw = generate_password_hash(password)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET name=?, email=?, password=? WHERE id=?', (name, email, hashed_pw, user_id))
    conn.commit()
    conn.close()

    session['user']['name'] = name
    session['user']['email'] = email

    return jsonify({'message': 'Profile updated successfully'}), 200

# --------------------------
# URL PREDICTION
# --------------------------
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Heuristic Check
    suspicious, reasons = check_url_heuristics(url)
    if suspicious:
        return jsonify({
            'url': url,
            'result': '⚠️ Suspicious (Heuristic)',
            'reasons': reasons,
            'method': 'heuristic'
        })

    # ML Model Prediction
    url_vectorized = vectorizer.transform([url])
    prediction = model.predict(url_vectorized)[0]
    labels = {0: "✅ Benign", 1: "⚠️ Phishing", 2: "🚨 Defacement"}

    return jsonify({
        'url': url,
        'result': labels.get(prediction, "❓ Unknown"),
        'method': 'ml'
    })

# --------------------------
# MODEL PERFORMANCE
# --------------------------
@app.route('/model_performance')
def model_performance():
    y_test = [0, 1, 0, 1, 0, 1]
    y_pred = [0, 1, 0, 0, 1, 1]
    return render_template(
        'model_performance.html',
        accuracy=accuracy_score(y_test, y_pred),
        precision=precision_score(y_test, y_pred),
        recall=recall_score(y_test, y_pred),
        f1=f1_score(y_test, y_pred)
    )

# --------------------------
# STATIC FILE FIX
# --------------------------
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# ============================================
# 🚀 Run Server
# ============================================
if __name__ == '__main__':
    print(f"Running from {BASE_DIR}")
    app.run(debug=True)
