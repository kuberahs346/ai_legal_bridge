from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime
from fpdf import FPDF
from flask import flash
import re
import threading
import webbrowser
import os
from werkzeug.security import generate_password_hash, check_password_hash


# Initialize app
app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# Uploads folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Upload model
class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('uploads', lazy=True))

# Root route
@app.route('/')
def root():
    return redirect(url_for('dashboard'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        phone = request.form.get('phone').strip()
        password = request.form.get('password')

        # Username validation
        if not re.fullmatch(r'^[A-Za-z0-9_]{3,}$', username):
            flash("Username must be at least 3 characters and contain only letters, numbers, or underscores.", "error")
            return redirect(url_for('signup'))

        # Phone validation
        if not re.match(r'^[0-9]{10}$', phone):
            flash("Phone number must be exactly 10 digits.", "error")
            return redirect(url_for('signup'))

        # Password validation
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', password):
            flash("Password must have 8+ chars, include uppercase, lowercase, number, and symbol.", "error")
            return redirect(url_for('signup'))
        
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))


        # Check duplicate phone
        if User.query.filter_by(phone=phone).first():
            flash("Phone number already registered.", "error")
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for('signup'))

        # Save user
        new_user = User(username=username, phone=phone, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


# Login

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # ✅ 1. Empty field check
        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for('login'))

        # ✅ 2. Username length check
        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "error")
            return redirect(url_for('login'))

        # ✅ 3. Password length check
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return redirect(url_for('login'))

        # ✅ 4. Check if user exists in DB
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("No account found with that username.", "error")
            return redirect(url_for('login'))

        # ✅ 5. Match password
        if user.password != password:
            flash("Incorrect password.", "error")
            return redirect(url_for('login'))
        

        # ✅ 6. Successful login
        session['user_logged_in'] = True
        session['user_id'] = user.id
        flash("Login successful!", "success")
        return redirect(url_for('index'))

        # When saving password
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, phone=phone, password=hashed_password)

        # When checking password
        if not check_password_hash(user.password, password):
          flash("Incorrect password", "error")
          return redirect(url_for("login"))

    return render_template('login.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Index after login
@app.route('/index')
def index():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')

# Upload
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['legal_file']
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            user_id = session.get('user_id')
            upload = Upload(filename=filename, user_id=user_id)
            db.session.add(upload)
            db.session.commit()

            user = User.query.get(user_id)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Generate certificate
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=14)
            pdf.cell(200, 10, txt="AI Legal Bridge - Document Submission Certificate", ln=True, align='C')
            pdf.ln(10)
            pdf.cell(200, 10, txt=f"User: {user.username}", ln=True)
            pdf.cell(200, 10, txt=f"Phone: {user.phone}", ln=True)
            pdf.cell(200, 10, txt=f"Document: {filename}", ln=True)
            pdf.cell(200, 10, txt=f"Submitted On: {now}", ln=True)

            cert_path = os.path.join(app.config['UPLOAD_FOLDER'], f"certificate_{filename}.pdf")
            pdf.output(cert_path)

            return f"""
                <h3 style='color:green;'>✅ File uploaded: {filename}</h3><br>
                <a href='/uploads/{filename}'><button>📥 Download Uploaded File</button></a><br><br>
                <a href='/uploads/certificate_{filename}.pdf'><button>🧾 Download Certificate</button></a><br><br>
                <a href='/index'><button style='padding:10px 20px;'>🔙 Back to Home</button></a>
            """
    return render_template('upload.html')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    

# Uploads view
@app.route('/uploads')
def view_uploads():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    uploads = Upload.query.filter_by(user_id=user_id).all()
    return render_template('uploads.html', uploads=uploads)

# File download
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Delete upload
@app.route('/delete/<int:upload_id>')
def delete_file(upload_id):
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    file_record = Upload.query.get_or_404(upload_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_record.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(file_record)
    db.session.commit()
    return redirect(url_for('view_uploads'))

# User Profile
@app.route('/profile', methods=['GET', 'POST'])
def user_profile():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.username = request.form['username']
        user.phone = request.form['phone']
        user.password = request.form['password']
        db.session.commit()
        return "<h3>✅ Profile updated</h3><a href='/index'>Back</a>"

    return render_template('profile.html', user=user)

# -------------------------
# ADMIN ROUTES
# -------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("⚠️ Both fields are required.", "error")
            return redirect(url_for('admin_login'))

        admin = User.query.filter_by(username=username, password=password, is_admin=True).first()
        if not admin:
            flash("❌ Invalid admin credentials.", "error")
            return redirect(url_for('admin_login'))

        session['admin_logged_in'] = True
        session['admin_id'] = admin.id
        flash("✅ Admin login successful!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_login.html')



@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    query = request.args.get('query', '')
    if query:
        users = User.query.filter(
            User.is_admin == False,
            (User.username.ilike(f'%{query}%')) | (User.phone.ilike(f'%{query}%'))
        ).all()
    else:
        users = User.query.filter_by(is_admin=False).all()

    return render_template('admin_dashboard.html', users=users, query=query)

@app.route('/admin/update/<int:user_id>', methods=['GET', 'POST'])
def admin_update(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.phone = request.form['phone']
        user.password = request.form['password']
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_update_user.html', user=user)

@app.route('/admin/delete/<int:user_id>')
def admin_delete(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/edit', methods=['GET', 'POST'])
def admin_edit_self():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    admin = User.query.get(session['admin_id'])
    if request.method == 'POST':
        admin.username = request.form['username']
        admin.password = request.form['password']
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_self.html', admin=admin)

# -------------------------
# EXPORT ROUTES
# -------------------------

@app.route('/admin/export/csv')
def export_users_csv():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = User.query.filter_by(is_admin=False).all()
    data = [['ID', 'Username', 'Phone', 'Password']] + [[u.id, u.username, u.phone, u.password] for u in users]
    csv_output = '\n'.join([','.join(map(str, row)) for row in data])
    response = make_response(csv_output)
    response.headers["Content-Disposition"] = "attachment; filename=users.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/admin/export/pdf')
def export_users_pdf():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    users = User.query.filter_by(is_admin=False).all()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="User List", ln=True, align='C')
    pdf.ln(10)
    for user in users:
        pdf.cell(200, 10, txt=f"ID: {user.id} | Name: {user.username} | Phone: {user.phone}", ln=True)

    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Disposition'] = 'attachment; filename=users.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

# -------------------------
# PAGES
# -------------------------

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/paste')
def paste():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))
    return render_template('paste.html')

@app.route('/history')
def upload_history():
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    uploads = Upload.query.filter_by(user_id=user_id).order_by(Upload.timestamp.desc()).all()
    return render_template('upload_history.html', uploads=uploads)

@app.route('/delete-upload/<int:upload_id>')
def delete_upload(upload_id):
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    upload = Upload.query.get_or_404(upload_id)
    if upload.user_id != session.get('user_id'):
        return "❌ Unauthorized", 403

    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload.filename))
        cert_path = os.path.join(app.config['UPLOAD_FOLDER'], f"certificate_{upload.filename}.pdf")
        if os.path.exists(cert_path):
            os.remove(cert_path)
    except Exception as e:
        print("File deletion error:", e)

    db.session.delete(upload)
    db.session.commit()
    return redirect(url_for('upload_history'))

# -------------------------
# Admin Creator & DB Reset
# -------------------------

@app.route('/create-admin')
def create_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin123', phone='9999999999', is_admin=True)
        db.session.add(admin)
        db.session.commit()
        return "✅ Admin created"
    return "⚠️ Admin already exists"

@app.route('/reset-db')
def reset_db():
    db.drop_all()
    db.create_all()
    return "✅ Database reset complete."

# -------------------------
# Run app
# -------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000/dashboard")).start()
    app.run(debug=True, use_reloader=False)
