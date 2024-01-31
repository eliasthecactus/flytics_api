from MySQLdb import IntegrityError
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from datetime import datetime, timedelta
import os
import secrets
import bcrypt
from uuid import uuid4
import binascii
import re
import imghdr
from PIL import Image
from kmlparser import *


app = Flask(__name__)
CORS(app)

raw_profile_picture_path = 'profile_pictures'

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
    pending_email = db.Column(db.String(120))
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



def checkPasswordStrenght(password):
    if len(password) < 8 or not any(char.islower() for char in password) or not any(char.isupper() for char in password) or not re.compile(r'[!@#$%^&*(),.?":{}|<>]').search(password):
        return False
    return True


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="99", message="Token expired"), 200

@app.errorhandler(Exception)
def generic_error(error):
    return jsonify({"message": "An unexpected error occurred"}), 400


@app.route('/api/ping')
def ping():
    return jsonify({"message": "pong"}), 200

@app.route('/api/authping')
@jwt_required()
def auth_ping():
    current_user = get_jwt_identity()
    return jsonify(code='0', message='pong'), 200

@app.route('/api/user/refresh', methods=['GET'])
@jwt_required()
def refresh_token():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(code="0", access_token=new_access_token), 200


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
        return jsonify(code='30', message='First name, Last name, Email, username, and password are required'), 200
    
    if User.query.filter_by(email=email).first():
        return jsonify(code='20', message='Email already in use'), 200
    
    if User.query.filter_by(username=username).first():
        return jsonify(code='10', message='Username already in use'), 200
    
    if not checkPasswordStrenght(password):
        return jsonify(code='40', message='Password to weak'), 200
    
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
        db.session.add(new_user)
        db.session.commit()
        # tbd send activation mail
        return jsonify(code="0", message='User registered successfully'), 200
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
                    if (user.deleted == False):
                        access_token = create_access_token(identity=user.id)
                        return jsonify(code='0', access_token=access_token)
                    else:
                        return jsonify(code='40', message='Account deleted'), 200
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
    resetemail = data.get('resetemail')
    token = data.get('token')
    password = data.get('password')

    if email:
        # tbd send email with token
        reset_token = binascii.hexlify(os.urandom(16)).decode()
        user = User.query.filter_by(email=email).first()
        if user:
            user.reset_token = reset_token
            user.reset_token_time = datetime.utcnow()
            db.session.commit()

        return jsonify(code="0", message='If there is a user with this email address, a reset link has been sent out'), 200
    else:
        if token:
            if resetemail:
                if password:
                    user = User.query.filter_by(email=resetemail).first()
                    if user:
                        if user.reset_token == token:

                            if user.reset_token_time < datetime.utcnow() - timedelta(hours=24):
                                user.reset_token = None
                                user.reset_token_time = None
                                db.session.commit()
                                return jsonify(code="70", message='Reset token expired'), 200

                            if not checkPasswordStrenght(password):
                                return jsonify(code="60", message='Password too weak'), 200
                            
                            new_hashed_password = bcrypt.hashpw(password.encode('utf-8'), user.salt.encode('utf-8'))


                            user.password = new_hashed_password
                            user.reset_token = None
                            user.reset_token_time = None

                            db.session.commit()

                            return jsonify(code="0", message='Password reset successfully'), 200


                        else:
                            return jsonify(code="50", message='Invalid Email/Token combination'), 200
                        
                    else:
                        return jsonify(code="50", message='Invalid Email/Token combination'), 200

                else:
                    return jsonify(code="30", message='Password is missing'), 200
            else:
                return jsonify(code="40", message='Email is missing'), 200
        else:
            return jsonify(code="20", message='Email/Token is missing'), 200




# tbd resend activation email

@app.route('/api/user/changepassword', methods=['POST'])
@jwt_required()
def password_change():
    current_user = get_jwt_identity()
    data = request.get_json()
    currentPassword = data.get('currentPassword')
    newPassword = data.get('newPassword')

    try:
        user = User.query.get(current_user)
        if user:
            if currentPassword:
                if newPassword:
                    if not checkPasswordStrenght(newPassword):
                        return jsonify(code='40', message='Password to weak'), 200
                    hashed_password = user.password
                    if bcrypt.checkpw(currentPassword.encode('utf-8'), hashed_password.encode('utf-8')):
                        new_hashed_password = bcrypt.hashpw(newPassword.encode('utf-8'), user.salt.encode('utf-8'))

                        user.password = new_hashed_password
                        db.session.commit()
                        # tbd sent password change confirmation mail
                        return jsonify(code='0', message='Password updated successfully'), 200
                    else:
                        return jsonify(code='50', message='Invalid credentials'), 200

                else:
                    return jsonify(code='40', message='Please provide the new password'), 200
            else:
                return jsonify(code='30', message='Please provide the current password'), 200
        else:
            return jsonify(code='20', message='There was an error while updating the account'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500


@app.route('/api/user/activate', methods=['GET'])
def activate_account():
    activation_token = request.args.get('token')

    if not activation_token:
        return jsonify(code='10', message='Activation token is missing'), 400

    user = User.query.filter_by(activation_token=activation_token).first()

    if user:
        user.activated = True
        user.activation_token = None
        if user.pending_email != None:
            user.email = user.pending_email
            user.pending_email = None
        db.session.commit()

        return jsonify(code='0', message='Account activated successfully'), 200
    else:
        return jsonify(code='20', message='Invalid activation token'), 400

@app.route('/api/user', methods=['PUT'])
@jwt_required()
def update_account():
    current_user = get_jwt_identity()
    data = request.get_json()
    new_first_name = data.get('first_name')
    new_last_name = data.get('last_name')
    new_username = data.get('username')
    new_email = data.get('email')


    try:
        user = User.query.get(current_user)
        if user:
            if new_first_name:
                user.first_name = new_first_name

            if new_last_name:
                user.last_name = new_last_name

            if new_username:
                if User.query.filter(User.id != current_user, User.username == new_username).first():
                    return jsonify(code='10',message='Username already in use'), 200
                if user.username != new_username:
                    user.username = new_username

            if new_email:
                if User.query.filter(User.id != current_user, User.username == new_username).first():
                    return jsonify(code='20',message='There is already an account with this Email-Address'), 200
                if user.email != new_email:
                    user.pending_email = new_email
                    user.activation_token = binascii.hexlify(os.urandom(20)).decode()

            db.session.commit()
            #tbd send mail with token

            return jsonify(code='0', message='Account updated successfully'), 200
        else:
            return jsonify(code='30', message='There was an error while updating the account'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500

@app.route('/api/user', methods=['DELETE'])
@jwt_required()
def delete_account():
    current_user = get_jwt_identity()
    # tbd token should be invalid after delete
    try:
        # print(current_user)
        user = User.query.get(current_user)

        if user:
            # Mark the user as deleted
            user.deleted = True
            user.deleted_at = datetime.utcnow()

            #tbd delete profile picture...
            db.session.commit()

            return jsonify(code='0', message='Account deleted successfully'), 200
        else:
            return jsonify(code='10', message='User not found'), 404
    except Exception as e:
        db.session.rollback()
        return jsonify(code='20', message=f'Error deleting account: {str(e)}'), 500
    
@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_account():
    current_user = get_jwt_identity()
    # tbd token should be invalid after delete
    try:
        print(current_user)
        user = User.query.get(current_user)

        if user:
            return jsonify(code='0', email=user.email, username=user.username, first_name=user.first_name, last_name=user.last_name, picture=user.profile_picture), 200
        else:
            return jsonify(code='10', message='User not found'), 404
    except Exception as e:
        db.session.rollback()
        return jsonify(code='20', message=f'Error while getting account information: {str(e)}'), 500

@app.route('/api/user/image', methods=['POST'])
@jwt_required()
def change_profile_picture():
    current_user = get_jwt_identity()

    # # take the image, save it to a temporary location (temp_images), crop it so it is a square, convert it to a png, resize it to 300x300, generate a random name (35 characters long), rename it to the randomname.png, save it to the image location (./profile_pictures/), add the random name to the database
    try:
        user = User.query.get(current_user)

        if user:
            if 'file' not in request.files:
                return jsonify(code='10', message='No file part'), 200
            
            file = request.files['file']

            if file.filename == '':
                return jsonify(code='20', message='No selected file'), 200
            

            os.makedirs(raw_profile_picture_path, exist_ok=True)


            if imghdr.what(file) not in ['jpeg', 'png']:
                return jsonify(code='10', message='Not a valid file. Please use a png or jpg/jpeg'), 200
            

            image_type = str(imghdr.what(file))
            filename = secrets.token_hex(16) + '.' + image_type.lower()
            file_path = os.path.join(raw_profile_picture_path, filename)



            img = Image.open(file)
            min_dimension = min(img.size)


            left = (img.width - min_dimension) // 2
            top = (img.height - min_dimension) // 2
            right = (img.width + min_dimension) // 2
            bottom = (img.height + min_dimension) // 2
            img_cropped = img.crop((left, top, right, bottom))


            img_resized = img_cropped.resize((512, 512))


            img_resized.save(file_path, quality=50)

            old_profile_picture_filename = user.profile_picture
            if old_profile_picture_filename:
                old_profile_picture_path = os.path.join(raw_profile_picture_path, old_profile_picture_filename)
                if os.path.exists(old_profile_picture_path):
                    os.remove(old_profile_picture_path)

            # file.save(file_path)

            user.profile_picture = filename
            db.session.commit()

            return jsonify(code='0', imageid=filename, message='Profile picture updated successfully'), 200
        else:
            return jsonify(code='40', message='User not found'), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(code='50', message=f'Error updating profile picture: {str(e)}'), 500
    
@app.route('/api/user/image', methods=['DELETE'])
@jwt_required()
def delete_profile_picture():
    current_user = get_jwt_identity()

    try:
        user = User.query.get(current_user)
        if user:
            profile_picture_filename = user.profile_picture

            if profile_picture_filename:

                # Construct the full path to the profile picture file
                profile_picture_path = os.path.join(raw_profile_picture_path, profile_picture_filename)

                if os.path.exists(profile_picture_path):
                    os.remove(profile_picture_path)
                else:
                    return jsonify(code='30', message='There was an error while deleting the profile picture. Please contact us or try later.'), 200


                user.profile_picture = None
                db.session.commit()

                return jsonify(code='0', message='Profile picture removed successfully'), 200
            else:
                # User does not have a profile picture
                return jsonify(code='10', message='User does not have a profile picture'), 200
        else:
            return jsonify(code='20', message='User not found'), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(code='30', message=f'Error removing profile picture: {str(e)}'), 500

@app.route('/api/user/image', methods=['GET'])
@jwt_required(optional=True)
def get_profile_picture():
    current_user = get_jwt_identity()
    profile_picture_filename = request.args.get('filename')
    try:
        if not profile_picture_filename:
            if not current_user:
                return jsonify(code='10', message='Filename is missing in the request'), 200
            else:
                user = User.query.get(current_user)
                if user:
                    if user.profile_picture:
                        profile_picture_file = user.profile_picture
        else:
            profile_picture_file = profile_picture_filename


        # if current_user:
        #     user = User.query.get(current_user)
        #     if user:
        #         if not profile_picture_filename:
        #             if user.profile_picture:
        #                 profile_picture_path = os.path.join(raw_profile_picture_path, user.profile_picture)
        #             else:
        #                 return jsonify(code='30', message='You do not have a profile picture'), 200
        #         else:
        #             profile_picture_path = os.path.join(raw_profile_picture_path, profile_picture_filename)
        # else:
        #     if not profile_picture_filename:
        #         return jsonify(code='10', message='Filename is missing in the request'), 200
        #     else:
        #         profile_picture_path = os.path.join(raw_profile_picture_path, profile_picture_filename)


        if os.path.exists(os.path.join(raw_profile_picture_path, profile_picture_file)):
            return send_from_directory(raw_profile_picture_path, profile_picture_file)
        else:
            return jsonify(code='20', message='Requested profile picture not found'), 200
    except Exception as e:
        return jsonify(code='50', message=f'Error retrieving profile picture: {str(e)}'), 500



# Routes for Flight Data Management

@app.route('/api/flights', methods=['POST'])
@jwt_required()
def upload_flight():
    current_user = get_jwt_identity()

    # Your implementation to handle file upload, extract data, and store in the database
    # ...

    # tbd multiple files (folder recursive)

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
