from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import os
import markdown2
from werkzeug.utils import secure_filename
import secrets
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from models import User, Article
from bson.errors import InvalidId

load_dotenv()

# MongoDB configuration
MONGODB_URI = "mongodb+srv://vercel-admin-user:HxS51lv17mRDPabZ@cluster0.whf8u94.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
DATA_API_URL = "https://data.mongodb-api.com/app/data-zzildve/endpoint/data/v1"
DATA_API_KEY = "QTp1p3xUvEU0vbamFDeFzXTgx1Tahfta0zm7lEqf8zZ6d74tx3IXxHoPvHYAqPNX"

# Set environment variables
os.environ['MONGODB_URI'] = MONGODB_URI
os.environ['DATA_API_URL'] = DATA_API_URL
os.environ['DATA_API_KEY'] = DATA_API_KEY

app = Flask(__name__, 
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['DEBUG'] = True

# MongoDB setup
mongodb_uri = os.environ['MONGODB_URI']
client = MongoClient(mongodb_uri)
db = client.get_database('myFirstDatabase')
users_collection = db.users
articles_collection = db.articles

login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User.from_db(user_data) if user_data else None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




@app.route('/')
def index():
    app.logger.debug("Rendering index template")
    page = request.args.get('page', 1, type=int)
    per_page = 5
    
    total = articles_collection.count_documents({})
    skip = (page - 1) * per_page
    
    try:
        articles_data = list(articles_collection.find({}).sort('created_at', -1).skip(skip).limit(per_page))
        articles = [Article.from_db(article_data) for article_data in articles_data if article_data]
    except Exception as e:
        app.logger.error(f"Error querying articles: {str(e)}")
        articles = []
    
    app.logger.debug(f"Articles: {articles}")
    app.logger.debug(f"Page: {page}, Per page: {per_page}, Total: {total}")
    
    return render_template('index.html', articles=articles, page=page, per_page=per_page, total=total)

@app.route('/article/<article_id>')
def view_article(article_id):
    article_data = articles_collection.find_one({'_id': ObjectId(article_id)})
    if article_data:
        article = Article.from_db(article_data)
        html = markdown2.markdown(article.content)
        return render_template('article.html', content=html, title=article.title)
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
        
        new_article = Article(title=title, content=content)
        articles_collection.insert_one(new_article.to_db())
        flash('Article created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/edit/<article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    article_data = articles_collection.find_one({'_id': ObjectId(article_id)})
    if not article_data:
        flash('Article not found', 'error')
        return redirect(url_for('index'))
    
    article = Article.from_db(article_data)
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('edit.html', article=article)
        
        article.update(title, content)
        articles_collection.update_one({'_id': ObjectId(article_id)}, {'$set': article.to_db()})
        flash('Article updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', article=article)

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
        user_data = users_collection.find_one({'username': username})
        if user_data:
            user = User.from_db(user_data)
            app.logger.debug(f"User found: {user.username}")
            if user.check_password(password):
                app.logger.debug("Password is correct")
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                app.logger.debug("Password is incorrect")
        else:
            app.logger.debug("User not found")
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/delete/<article_id>')
@login_required
def delete_article(article_id):
    result = articles_collection.delete_one({'_id': ObjectId(article_id)})
    if result.deleted_count:
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
        existing_user = users_collection.find_one({'username': username})
        if existing_user is None:
            new_user = User(username=username)
            new_user.set_password(password)
            users_collection.insert_one(new_user.to_db())
            app.logger.info(f"Admin user '{username}' created successfully.")
        else:
            app.logger.info(f"Admin user '{username}' already exists.")
    except Exception as e:
        app.logger.error(f"Error creating admin user: {str(e)}")

if __name__ == '__main__':
    create_admin('admin', 'Jungdala')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.logger.info("Starting server on http://localhost:5001")
    app.run(debug=True, host='localhost', port=5001)