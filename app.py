from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

# Initialise extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
Talisman(app)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"]
)

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    owner = db.Column(db.String(80), nullable=False)

# Home route
@app.route('/')
def home():
    return jsonify({"message": "Secure Notes API Running"})

# Register route
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():

    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    # Basic validation

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    if password.lower() == password or password.upper() == password:
        return jsonify({"error": "Password must contain both uppercase and lowercase letters"}), 400

    if not any(char.isdigit() for char in password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    # Prevent duplicate users
    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({"error": "User already exists"}), 409

    # Hash password securely
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(
        username=username,
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login route
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():

    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)

    return jsonify(access_token=access_token), 200

# Protected route
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():

    current_user = get_jwt_identity()

    return jsonify({
        "message": f"Welcome {current_user}",
        "status": "Authenticated"
    })

@app.route('/notes', methods=['POST'])
@jwt_required()
def create_note():

    current_user = get_jwt_identity()
    data = request.get_json()

    content = data.get("content")

    if not content:
        return jsonify({"error": "Note content is required"}), 400

    if len(content) > 300:
        return jsonify({"error": "Note content must be under 300 characters"}), 400

    new_note = Note(
        content=content,
        owner=current_user
    )

    db.session.add(new_note)
    db.session.commit()

    return jsonify({"message": "Note created successfully"}), 201


@app.route('/notes', methods=['GET'])
@jwt_required()
def get_notes():

    current_user = get_jwt_identity()

    notes = Note.query.filter_by(owner=current_user).all()

    results = []

    for note in notes:
        results.append({
            "id": note.id,
            "content": note.content
        })

    return jsonify(results), 200

# Run application
if __name__ == '__main__':

    with app.app_context():
        db.create_all()

    app.run(debug=True)