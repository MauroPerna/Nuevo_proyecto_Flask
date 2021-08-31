from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'colaboradores'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    fecha_inicio_actividad = db.Column(db.String(120), unique=False, nullable=False)
    monto_inicial = db.Column(db.String(120), unique=False, nullable=False)
    fecha_ultima_actualizacion = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)