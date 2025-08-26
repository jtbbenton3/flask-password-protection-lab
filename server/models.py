from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String)

    
    @hybrid_property
    def password_hash(self):
        raise AttributeError("password_hash is not a readable attribute")

    
    @password_hash.setter
    def password_hash(self, password):
        if password is None:
            raise ValueError("Password cannot be None")
        pw_hash = bcrypt.generate_password_hash(password)
        
        self._password_hash = pw_hash.decode("utf-8") if isinstance(pw_hash, (bytes, bytearray)) else pw_hash

    
    def authenticate(self, password):
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(self._password_hash, password)

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()