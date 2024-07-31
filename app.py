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
import redis
import json

load_dotenv()

app = Flask(__name__, 
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['DEBUG'] = True  # Enable debug mode
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///admin.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Connect to Vercel KV (Redis)
redis_url = os.getenv('KV_URL')
redis_client = redis.from_url(redis_url)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    app.logger.debug("Rendering index template")
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of articles per page
    
    # Get all article keys from Redis
    article_keys = redis_client.keys('article:*')
    articles = []
    for key in article_keys:
        article_data = json.loads(redis_client.get(key))
        articles.append({'title': article_data['title'], 'filename': key.decode().split(':')[1]})
    
    total = len(articles)
    articles = articles[(page-1)*per_page:page*per_page]
    
    app.logger.debug(f"Articles: {articles}")
    app.logger.debug(f"Page: {page}, Per page: {per_page}, Total: {total}")
    
    return render_template('index.html', articles=articles, page=page, per_page=per_page, total=total)

@app.route('/article/<filename>')
def view_article(filename):
    article_data = redis_client.get(f'article:{filename}')
    if article_data:
        article = json.loads(article_data)
        html = markdown2.markdown(article['content'])
        return render_template('article.html', content=html)
    else:
        flash("Article not found", 'error')
        return redirect(url_for('index'))

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
        
        article_filename = title.lower().replace(' ', '-')
        article_data = {
            'title': title,
            'content': content
        }
        redis_client.set(f'article:{article_filename}', json.dumps(article_data))
        flash('Article created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/edit/<filename>', methods=['GET', 'POST'])
@login_required
def edit_article(filename):
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('edit.html', filename=filename, title=title, content=content)
        
        article_data = {
            'title': title,
            'content': content
        }
        redis_client.set(f'article:{filename}', json.dumps(article_data))
        flash('Article updated successfully!', 'success')
        return redirect(url_for('index'))
    
    article_data = redis_client.get(f'article:{filename}')
    if article_data:
        article = json.loads(article_data)
        return render_template('edit.html', filename=filename, title=article['title'], content=article['content'])
    else:
        flash('Article not found', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    
    app.logger.debug("Login route accessed")
    if request.method == 'POST':
        app.logger.debug("POST request received")
        username = request.form.get('username')
        password = request.form.get('password')
        app.logger.debug(f"Login attempt: username='{username}', password='{password}'")
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            app.logger.debug(f"Admin found: {admin.username}")
            if admin.check_password(password):
                app.logger.debug("Password is correct")
                login_user(admin)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                app.logger.debug("Password is incorrect")
        else:
            app.logger.debug("Admin not found")
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/delete/<filename>')
@login_required
def delete_article(filename):
    if redis_client.delete(f'article:{filename}'):
        flash('Article deleted successfully!', 'success')
    else:
        flash('Error deleting the article', 'error')
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
    app.logger.error(f"Unhandled exception: {str(e)}")
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
        app.logger.info(f"Password hash: {admin.password_hash}")
        
        # Verify the admin exists and password works
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            app.logger.info("Admin credentials are correct.")
        else:
            app.logger.error("Failed to verify admin credentials.")
        
        # Print all users in the database
        all_users = Admin.query.all()
        for user in all_users:
            app.logger.info(f"User: {user.username}, Password hash: {user.password_hash}")
    except Exception as e:
        app.logger.error(f"Error creating admin user: {str(e)}")
        db.session.rollback()

def reset_database():
    with app.app_context():
        db.drop_all()
        db.create_all()
        create_admin('admin', 'Jungdala')
        app.logger.info("Database reset and admin user created")

if __name__ == '__main__':
    reset_database()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.logger.info("Starting server on http://localhost:5001")
    app.run(debug=True, host='localhost', port=5001)