from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from bson import ObjectId
from datetime import datetime

class User(UserMixin):
    def __init__(self, username, password_hash=None, _id=None):
        self.username = username
        self.password_hash = password_hash
        self._id = _id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self._id)

    @staticmethod
    def from_db(user_data):
        if not user_data:
            return None
        return User(
            username=user_data['username'],
            password_hash=user_data['password_hash'],
            _id=user_data['_id']
        )

    def to_db(self):
        return {
            'username': self.username,
            'password_hash': self.password_hash
        }

class Article:
    def __init__(self, title, content, created_at=None, updated_at=None, _id=None):
        self.title = title
        self.content = content
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
        self._id = _id

    @staticmethod
    def from_db(article_data):
        if not article_data:
            return None
        return Article(
            title=article_data['title'],
            content=article_data['content'],
            created_at=article_data['created_at'],
            updated_at=article_data['updated_at'],
            _id=article_data['_id']
        )

    def to_db(self):
        return {
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    def update(self, title, content):
        self.title = title
        self.content = content
        self.updated_at = datetime.utcnow()