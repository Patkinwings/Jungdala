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

ARTICLES_DIR = 'articles'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

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
    articles = []
    if os.path.exists(ARTICLES_DIR):
        for filename in os.listdir(ARTICLES_DIR):
            if filename.endswith('.md'):
                try:
                    with open(os.path.join(ARTICLES_DIR, filename), 'r') as f:
                        content = f.read()
                        title = content.split('\n')[0].strip('#').strip()
                        articles.append({'title': title, 'filename': filename[:-3]})
                except IOError:
                    app.logger.error(f"Error reading file: {filename}")
    
    total = len(articles)
    articles = articles[(page-1)*per_page:page*per_page]
    
    app.logger.debug(f"Articles: {articles}")
    app.logger.debug(f"Page: {page}, Per page: {per_page}, Total: {total}")
    
    return render_template('index.html', articles=articles, page=page, per_page=per_page, total=total)

@app.route('/article/<filename>')
def view_article(filename):
    try:
        with open(os.path.join(ARTICLES_DIR, f'{filename}.md'), 'r') as f:
            content = f.read()
            html = markdown2.markdown(content)
        return render_template('article.html', content=html)
    except IOError:
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
        
        article_filename = title.lower().replace(' ', '-') + '.md'
        try:
            with open(os.path.join(ARTICLES_DIR, article_filename), 'w') as f:
                f.write(f'# {title}\n\n{content}')
            flash('Article created successfully!', 'success')
        except IOError:
            flash('Error saving the article', 'error')
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
        
        try:
            with open(os.path.join(ARTICLES_DIR, f'{filename}.md'), 'w') as f:
                f.write(f'# {title}\n\n{content}')
            flash('Article updated successfully!', 'success')
        except IOError:
            flash('Error updating the article', 'error')
        return redirect(url_for('index'))
    
    try:
        with open(os.path.join(ARTICLES_DIR, f'{filename}.md'), 'r') as f:
            content = f.read()
            title = content.split('\n')[0].strip('#').strip()
            body = '\n'.join(content.split('\n')[2:])
        return render_template('edit.html', filename=filename, title=title, content=body)
    except IOError:
        flash('Article not found', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
    
    print("Login route accessed")
    if request.method == 'POST':
        print("POST request received")
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login attempt: username='{username}', password='{password}'")
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            print(f"Admin found: {admin.username}")
            if admin.check_password(password):
                print("Password is correct")
                login_user(admin)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                print("Password is incorrect")
        else:
            print("Admin not found")
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/delete/<filename>')
@login_required
def delete_article(filename):
    try:
        os.remove(os.path.join(ARTICLES_DIR, f'{filename}.md'))
        flash('Article deleted successfully!', 'success')
    except OSError:
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
    admin = Admin.query.filter_by(username=username).first()
    if admin is None:
        admin = Admin(username=username)
        db.session.add(admin)
    admin.set_password(password)
    db.session.commit()
    print(f"Admin user '{username}' created/updated successfully.")
    
    # Verify the admin exists and password works
    admin = Admin.query.filter_by(username=username).first()
    if admin and admin.check_password(password):
        print("Admin credentials are correct.")
    else:
        print("Failed to verify admin credentials.")

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Add this line to delete the existing database
        db.create_all()
        create_admin('admin', '1234')  # Using your test password
    os.makedirs(ARTICLES_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("Starting server on http://localhost:5001")
    app.run(debug=True, host='localhost', port=5001)