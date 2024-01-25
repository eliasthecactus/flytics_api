from MySQLdb import IntegrityError
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import secrets
import bcrypt
from uuid import uuid4
import binascii
import re

app = Flask(__name__)
CORS(app)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://user:password@127.0.0.1:3306/db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_secret_key')

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Define User and Flight models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    profile_picture = db.Column(db.String(40))
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    enabled = db.Column(db.Boolean, default=True)
    activation_token = db.Column(db.String(255))
    activated = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(255))
    reset_token_time = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    info = db.Column(db.String(255))

class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date)
    time = db.Column(db.Time)
    timezone = db.Column(db.String(60))
    coordinates = db.Column(db.Integer)
    public = db.Column(db.Boolean, default=True)
    original_filename = db.Column(db.String(255))
    filename = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    info = db.Column(db.String(255))




@app.errorhandler(401)
def token_expired(error):
    return jsonify({"message": "Token has expired"}), 401

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({"message": "404 Not Found"}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"message": "Internal Server Error"}), 500

# @app.errorhandler(Exception)
# def generic_error(error):
#     return jsonify({"message": "An unexpected error occurred"}), 500


@app.route('/api/ping')
def ping():
    return jsonify({"message": "pong"}), 200

@app.route('/api/authping')
@jwt_required()
def auth_ping():
    current_user = get_jwt_identity()
    return jsonify({"message": "pong, you are nr "+str(current_user)}), 200

@app.route('/api/user/availability', methods=['GET'])
def check_availability():
    username = request.args.get('username')

    if not username:
        return jsonify(code='20', message='Username is required'), 400

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify(code='10', message='Username already in use'), 200
    else:
        return jsonify(code='0', message='Username available'), 200


@app.route('/api/user/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    password = data.get('password')

    if not email or not username or not password or not first_name or not last_name:
        return jsonify(code='30', message='First name, Last name, Email, username, and password are required'), 400
    
    # Validation: Check if the email and username are unique
    if User.query.filter_by(email=email).first():
        return jsonify(code='20', message='Email already in use'), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify(code='10', message='Username already in use'), 400
    
    if len(password) < 8 or not any(char.islower() for char in password) or not any(char.isupper() for char in password) or not re.compile(r'[!@#$%^&*(),.?":{}|<>]').search(password):
        return jsonify(code='40', message='Password to weak'), 400
    
    encoded_password = password.encode('utf-8')

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(encoded_password, salt)

    activation_token = binascii.hexlify(os.urandom(20)).decode()

    new_user = User(
        email=email,
        username=username,
        first_name=first_name,
        last_name=last_name,
        password=hashed_password,
        activation_token=activation_token,
        salt=salt
    )

    try:
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        # send activation mail
        return jsonify(message='User registered successfully'), 201
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error registering user: {str(e)}'), 500



@app.route('/api/user/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    
    if user:
        hashed_password = user.password

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            if (user.activated == True):
                if (user.enabled == True):
                    access_token = create_access_token(identity=user.id)
                    return jsonify(code='0', access_token=access_token)
                else:
                    return jsonify(code='10', message='Account disabled'), 200
            else:
                return jsonify(code='20', message='Account not activated'), 200

        else:
            return jsonify(code='30', message='Invalid credentials'), 200
    else:
        return jsonify(code='30', message='Invalid credentials'), 200

@app.route('/api/user/resetpassword', methods=['POST'])
def password_forgot():
    data = request.get_json()
    email = data.get('email')

    #tbd



    return jsonify(message='Password reset link sent successfully')

@app.route('/api/user/activate', methods=['GET'])
def activate_account():
    activation_token = request.args.get('token')

    #tbd


    return jsonify(message='Activated successfully')

@app.route('/api/user', methods=['PUT'])
@jwt_required()
def update_account():
    current_user = get_jwt_identity()
    user_id = current_user.get('id')

    data = request.get_json()
    new_first_name = data.get('first_name')
    new_last_name = data.get('last_name')
    new_username = data.get('username')


    try:
        user = User.query.get(user_id)
        if user:
            # Update the first name if provided
            if new_first_name:
                user.first_name = new_first_name

            # Update the last name if provided
            if new_last_name:
                user.last_name = new_last_name

            # Update the username if provided and unique
            if new_username:
                if User.query.filter(User.id != user_id, User.username == new_username).first():
                    return jsonify(message='Username already in use'), 400
                user.username = new_username

            # Your implementation to update other information if needed

            db.session.commit()
            return jsonify(message='Account updated successfully')
        else:
            return jsonify(message='User not found'), 404
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500

@app.route('/api/user', methods=['DELETE'])
@jwt_required()
def delete_account():
    current_user = get_jwt_identity()

    #tbd

    return jsonify(code='0', message='Account deleted successfully')



# Routes for Flight Data Management

@app.route('/api/flights', methods=['POST'])
@jwt_required()
def upload_flight():
    current_user = get_jwt_identity()

    # Your implementation to handle file upload, extract data, and store in the database
    # ...

    return jsonify(message='Flight uploaded successfully')

@app.route('/api/flights/<int:flight_id>', methods=['DELETE'])
@jwt_required()
def delete_flight(flight_id):
    current_user = get_jwt_identity()
    user_id = current_user.get('id')

    # Your implementation to check ownership and delete the specified flight entry
    # ...

    return jsonify(message=f'Flight {flight_id} deleted successfully')

@app.route('/api/flights/<int:flight_id>', methods=['GET'])
@jwt_required()
def get_flight(flight_id):
    current_user = get_jwt_identity()
    user_id = current_user.get('id')

    # Your implementation to check ownership and provide download link for the specified flight
    # ...

    return jsonify(message=f'Download Flight {flight_id} endpoint')

@app.route('/api/flights/<int:flight_id>/download', methods=['GET'])
@jwt_required()
def download_flight(flight_id):
    current_user = get_jwt_identity()
    user_id = current_user.get('id')

    # Your implementation to check ownership and provide download link for the specified flight
    # ...

    return jsonify(message=f'Download Flight {flight_id} endpoint')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
