from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os
import markdown2
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import logging
from dotenv import load_dotenv
from datetime import timedelta, datetime
import sys

print("Python version:", sys.version)
print("Python path:", sys.path)

load_dotenv()

app = Flask(__name__, 
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['DEBUG'] = False  # Disable debug mode for production

database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+pg8000://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.INFO)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

@app.after_request
def add_csp_header(response):
    csp = "default-src 'self' https://cdn.tiny.cloud; " \
          "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tiny.cloud; " \
          "style-src 'self' 'unsafe-inline' https://cdn.tiny.cloud; " \
          "img-src 'self' data: blob: https://cdn.tiny.cloud https://sp.tinymce.com; " \
          "font-src 'self' https://cdn.tiny.cloud; " \
          "connect-src 'self' https://cdn.tiny.cloud https://sp.tinymce.com;"
    response.headers['Content-Security-Policy'] = csp
    return response

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    app.logger.info("Rendering index template")
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of articles per page
    articles = Article.query.order_by(Article.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('index.html', articles=articles)

@app.route('/article/<int:article_id>')
def view_article(article_id):
    article = Article.query.get_or_404(article_id)
    html_content = markdown2.markdown(article.content)
    return render_template('article.html', article=article, content=html_content)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('admin.html')
        
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    content += f"\n\n![{filename}](/static/uploads/{filename})"
                except Exception as e:
                    flash(f'Error uploading file: {str(e)}', 'error')
                    return render_template('admin.html')
        
        new_article = Article(title=title, content=content)
        db.session.add(new_article)
        try:
            db.session.commit()
            flash('Article created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating article: {str(e)}', 'error')
            return render_template('admin.html')
        
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/edit/<int:article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('edit.html', article=article)
        
        article.title = title
        article.content = content
        
        try:
            db.session.commit()
            flash('Article updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating article: {str(e)}', 'error')
            return render_template('edit.html', article=article)
        
        return redirect(url_for('view_article', article_id=article.id))
    
    return render_template('edit.html', article=article)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    
    app.logger.info("Login route accessed")
    if request.method == 'POST':
        app.logger.info("POST request received")
        username = request.form.get('username')
        password = request.form.get('password')
        app.logger.info(f"Login attempt: username='{username}'")
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin:
            app.logger.info(f"Admin found: {admin.username}")
            if admin.check_password(password):
                app.logger.info("Password is correct")
                login_user(admin, remember=True)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                app.logger.info("Password is incorrect")
        else:
            app.logger.info("Admin not found")
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/delete/<int:article_id>')
@login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    try:
        db.session.delete(article)
        db.session.commit()
        flash('Article deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting the article: {str(e)}', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"404 error: {str(e)}")
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return "An error occurred", 500

@app.route('/about')
def about():
    return render_template('about.html')

def create_admin(username, password):
    try:
        admin = Admin.query.filter_by(username=username).first()
        
        if admin is None:
            admin = Admin(username=username)
            db.session.add(admin)
        admin.set_password(password)
        db.session.commit()
        
        app.logger.info(f"Admin user '{username}' created/updated successfully.")
        
        # Verify the admin exists and password works
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and admin.check_password(password):
            app.logger.info("Admin credentials are correct.")
        else:
            app.logger.error("Failed to verify admin credentials.")
    except Exception as e:
        app.logger.error(f"Error creating admin user: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin('admin', 'Jungdala')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.logger.info("Starting server on http://localhost:5001")
    app.run(debug=False, host='localhost', port=5001)