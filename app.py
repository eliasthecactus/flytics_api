from MySQLdb import IntegrityError
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
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
import hashlib
from sqlalchemy import func, or_
from postmarker.core import PostmarkClient



app = Flask(__name__)
CORS(app)


postmark = PostmarkClient(server_token='4b1f4a36-cf94-40fe-8588-f773cea34972', account_token='9a32a58c-d43a-4d24-92ba-9f26aad3f179', verbosity=3)

script_path = os.path.dirname(os.path.realpath(__file__))
raw_profile_picture_path = os.path.join(script_path, "profile_pictures")
raw_igc_files_path = os.path.join(script_path, "igc_files")

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://user:password@127.0.0.1:3306/db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_secret_key')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

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
    # timestamp = db.Column(db.Integer)
    start_time = db.Column(db.DateTime)
    timezone = db.Column(db.String(60))
    country = db.Column(db.String(60))
    country_code = db.Column(db.String(10))
    location = db.Column(db.String(60))
    distance = db.Column(db.Integer)
    start_lat = db.Column(db.Float)
    start_long = db.Column(db.Float)
    start_height = db.Column(db.Integer)
    end_height = db.Column(db.Integer)
    duration = db.Column(db.Integer)
    timezone_raw_offset = db.Column(db.Integer)
    timezone_dst_offset = db.Column(db.Integer)
    public = db.Column(db.Boolean)
    igc_file = db.Column(db.String(50))
    igc_sum=db.Column(db.String(32))
    kml_file = db.Column(db.String(50))
    geojson_file = db.Column(db.String(50))
    uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    info = db.Column(db.String(255))
    
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)





def checkPasswordStrenght(password):
    if len(password) < 8 or not any(char.islower() for char in password) or not any(char.isupper() for char in password) or not re.compile(r'[!@#$%^&*(),.?":{}|<>]').search(password):
        return False
    return True


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="99", message="Token expired"), 200

@app.errorhandler(Exception)
def generic_error(error):
    print(error)
    return jsonify({"message": "An unexpected error occurred"}), 400


@app.route('/api/ping')
def ping():
    return jsonify({"message": "pong"}), 200

@app.route('/api/authping')
@jwt_required()
def auth_ping():
    current_user = get_jwt_identity()
    return jsonify(code='0', message='pong', user=current_user), 200


# # not implemented yet
# @app.route('/api/getlocation', methods=['GET'])
# @jwt_required()
# def get_location_string():
#     current_user = get_jwt_identity()
#     # Check if the location is already in the database
#     base_query = LocationStorage.query
#     tolerance = 0.04
#     base_query = base_query.filter(LocationStorage.lat.between(lat - tolerance, lat + tolerance), LocationStorage.long.between(long - tolerance, long + tolerance))
#     if base_query.count() > 0:
#         print("There is an available location")
#         result = base_query.first()
#         return {'country': result.country, 'country_code': result.country_code, 'location': result.location}
#     else:
#         print("Location not found in the database")
    
#     try:
#         lat = float(request.args.get('lat'))
#         long = float(request.args.get('long'))
#     except:
#         return jsonify(code='30', message='Invalid parameter format'), 200
#     if not long or not lat:
#         return jsonify(code='20', message='Invalid parameters'), 200

#     location = get_location(lat=lat, long=long)
#     if location['location'] is None:
#         return jsonify(code='10', message='No valid location found'), 200
    
#     return jsonify(code='0', message=location['location']), 200


    

# @app.route('/api/user/refresh', methods=['GET'])
# @jwt_required()
# def refresh_token():
#     current_user = get_jwt_identity()
#     new_access_token = create_access_token(identity=current_user)
#     return jsonify(code="0", access_token=new_access_token), 200




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
        postmark.emails.send_with_template(
            TemplateId=34843478,
            TemplateModel={
                'product_name': 'flytics',
                'action_url': activation_token},
            From='flytics@elias.uno',
            To=email,
        )
        # 34843719
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
                        return jsonify(code='0', access_token=access_token, user=user.id)
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


@app.route("/api/user/logout", methods=["DELETE"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(code=0, message="JWT revoked")


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
            while True:
                filename = secrets.token_hex(16) + '.' + image_type.lower()
                file_path = os.path.join(raw_profile_picture_path, filename)

                if not os.path.exists(file_path):
                    break



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







@app.route('/api/flights', methods=['POST'])
@jwt_required()
def upload_flight():
    current_user = get_jwt_identity()
    try:
        user = User.query.get(current_user)
        if user:
            if 'file' not in request.files:
                return jsonify(code='10', message='No file part'), 200
            
            file = request.files['file']

            if file.filename == '':
                return jsonify(code='20', message='No selected file'), 200
            
            max_file_size = 0.1 * 1024 * 1024
            if file.content_length > max_file_size:
                return jsonify(code='70', message='File size exceeds the limit of 5 MB'), 200
            


            if request.form.get('private'):
                flight_private_str = request.form.get('private')
                flight_private = flight_private_str.lower() == 'true'
            else:
                flight_private = False
                
                
            
            flight_information = request.form.get('information')

            

            os.makedirs(raw_igc_files_path, exist_ok=True)


            while True:
                filename = secrets.token_hex(16) + '.' + "igc"
                file_path = os.path.join(raw_igc_files_path, filename)

                if not os.path.exists(file_path):
                    break



            file.save(file_path)

            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    md5_hash.update(byte_block)
            md5_value = md5_hash.hexdigest()
            # print(md5_value)


            existing_flight = Flight.query.filter_by(user_id=user.id, igc_sum=md5_value).first()
            if existing_flight:
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify(code='60', message='Duplicate flight. The same flight is already available.'), 200
            

            current_flight_data = parse_igc(file_path, str(user.first_name) + " " + str(user.last_name))
            if (current_flight_data['code'] != 0):
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify(code='80', message=current_flight_data['message']), 200


            utc_datetime = datetime.utcfromtimestamp(current_flight_data['timestamp'])

            print(current_flight_data)

            if current_flight_data['code'] == 0:
                new_flight = Flight(
                    user_id=user.id,
                    timezone=current_flight_data['timezone_id'],
                    # timestamp=current_flight_data['timestamp'],
                    start_time=utc_datetime,
                    country=current_flight_data['country'],
                    country_code=current_flight_data['country_code'],
                    location=current_flight_data['location'],
                    distance=current_flight_data['distance'],
                    start_lat=current_flight_data['start_lat'],
                    start_long=current_flight_data['start_long'],
                    start_height=current_flight_data['start_height'],
                    end_height=current_flight_data['end_height'],
                    duration=current_flight_data['duration'],
                    timezone_raw_offset=current_flight_data['timezone_raw_offset'],
                    timezone_dst_offset=current_flight_data['timezone_dst_offset'],
                    public=not flight_private,
                    igc_file=filename,
                    igc_sum=md5_value,
                    kml_file=current_flight_data['kml_file'],
                    geojson_file=current_flight_data['geojson_file'],
                    info=flight_information
                )

                db.session.add(new_flight)
                db.session.commit()
                return jsonify(code='0', message='Flight imported successfully'), 200
            else:
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify(code='30', message=current_flight_data['message']), 200
                
        else:
            return jsonify(code='40', message='User not found'), 200
    except Exception as e:
        # tbd del gen kml files if fail
        if os.path.exists(os.path.join(script_path + "/kml_files/" + current_flight_data['kml_file'])):
            os.remove(os.path.join(script_path + "/kml_files/" + current_flight_data['kml_file']))
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.rollback()
        return jsonify(code='50', message=f'There was an error while uploading the flight: {str(e)}'), 500


@app.route('/api/flights/<int:flight_id>', methods=['DELETE'])
@jwt_required()
def delete_flight(flight_id):
    current_user = get_jwt_identity()
    
    try:
        user = User.query.get(current_user)
        
        if not user:
            return jsonify(code='20', message=f'User not found')
        
        flight = Flight.query.filter_by(id=flight_id, user_id=user.id).first()
        if not flight:
            return jsonify(code='30', message=f'Flight {flight_id} not found or does not belong to the user'), 200
        
        if os.path.exists(os.path.join(script_path + "/kml_files/" + flight.kml_file)):
            os.remove(os.path.join(script_path + "/kml_files/" + flight.kml_file))
        if os.path.exists(os.path.join(script_path + "/igc_files/" + flight.igc_file)):
            os.remove(os.path.join(script_path + "/igc_files/" + flight.igc_file))

        db.session.delete(flight)
        db.session.commit()

        return jsonify(code='0', message=f'Flight {flight_id} deleted successfully'), 200

    except Exception as e:
        db.session.rollback()
        return jsonify(code='50', message=f'Error deleting flight: {str(e)}'), 500


# @app.route('/api/flights/<int:flight_id>', methods=['GET'])
# @jwt_required()
# def get_flight_details(flight_id):
#     current_user = get_jwt_identity()

#     user = User.query.get(current_user)

#     if not user:
#         return jsonify(code='20', message='User not found'), 200

#     # flight = Flight.query.filter_by(id=flight_id, user_id=user.id).first()
#     flight = Flight.query.filter((Flight.id == flight_id) & ((Flight.user_id == user.id) | (Flight.public == True))).first()

#     if not flight:
#         return jsonify(code='30', message=f'Flight {flight_id} not found or not accessible'), 404

#     # Convert datetime objects to string for JSON serialization
#     flight_details = {
#         'id': flight.id,
#         'user_id': flight.user_id,
#         'start_time': str(flight.start_time),
#         'timezone': flight.timezone,
#         'country': flight.country,
#         'country_code': flight.country_code,
#         'location': flight.location,
#         'distance': flight.distance,
#         'start_lat': flight.start_lat,
#         'start_long': flight.start_long,
#         'start_height': flight.start_height,
#         'end_height': flight.end_height,
#         'duration': flight.duration,
#         'timezone_raw_offset': flight.timezone_raw_offset,
#         'timezone_dst_offset': flight.timezone_dst_offset,
#         'public': flight.public,
#         # 'igc_file': flight.igc_file,
#         'igc_sum': flight.igc_sum,
#         # 'kml_file': flight.kml_file,
#         'uploaded': str(flight.uploaded),
#         'info': flight.info
#     }
#     return jsonify(code='0', flight=flight_details), 200



@app.route('/api/flights', methods=['GET'])
@jwt_required()
def get_flights():
    current_user = get_jwt_identity()
    
    user = User.query.get(current_user)
    
    if not user:
        return jsonify(code='20', message='User not found'), 200
    
    try:
        user_id_str = request.args.get('user')
        flight_id_str = request.args.get('flight_id')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        location_lat = request.args.get('location_lat')
        location_long = request.args.get('location_long')
        location_range_min = request.args.get('location_range_min')
        location_range_max = request.args.get('location_range_max')
        start_height_min = request.args.get('start_height_min')
        start_height_max = request.args.get('start_height_max')
        end_height_min = request.args.get('end_height_min')
        end_height_max = request.args.get('end_height_max')
        distance_min = request.args.get('distance_min')
        distance_max = request.args.get('distance_max')
        duration_min = request.args.get('duration_min')
        duration_max = request.args.get('duration_max')
        stats_enabled = 'stats' in request.args        

        # Base query for the user's flights
        base_query = Flight.query

        
        if user_id_str:
            flight_user = User.query.get(user_id_str)
            if flight_user:
                if user == flight_user:
                    base_query = base_query.filter(Flight.user_id == user.id)
                else:
                    base_query = base_query.filter(Flight.user_id == flight_user.id, Flight.public == True)
            else:
                return jsonify(code='30', message="User does not exist"), 200
        else:
            base_query = base_query.filter(or_(Flight.user_id == current_user, Flight.public == True))

        # Additional condition for flight_id_str
        if flight_id_str:
            base_query = base_query.filter(Flight.id == flight_id_str)


        
        # Parse date parameters
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
        
        # Apply date range filter
        if start_date:
            base_query = base_query.filter(Flight.start_time >= start_date)
        if end_date:
            base_query = base_query.filter(Flight.start_time <= end_date)

        # Apply start_height range filter
        if start_height_min:
            base_query = base_query.filter(Flight.start_height >= int(start_height_min))
        if start_height_max:
            base_query = base_query.filter(Flight.start_height <= int(start_height_max))
            
        # Apply start_height range filter
        if end_height_min:
            base_query = base_query.filter(Flight.end_height >= int(end_height_min))
        if end_height_max:
            base_query = base_query.filter(Flight.end_height <= int(end_height_max))

        # Apply distance range filter
        if distance_min:
            base_query = base_query.filter(Flight.distance >= int(distance_min))
        if distance_max:
            base_query = base_query.filter(Flight.distance <= int(distance_max))

        # Apply duration range filter
        if duration_min:
            base_query = base_query.filter(Flight.duration >= int(duration_min))
        if duration_max:
            base_query = base_query.filter(Flight.duration <= int(duration_max))
        

        # Execute the final query
        filtered_flights = base_query.all()
        
        if location_lat and location_long:
            if location_range_min or location_range_max:
                filtered_flights = [
            flight for flight in filtered_flights if (location_range_min is None or calculate_distance(float(location_lat), float(location_long), float(flight.start_lat), float(flight.start_long)) >= float(location_range_min)) and (location_range_max is None or calculate_distance(float(location_lat), float(location_long), float(flight.start_lat), float(flight.start_long)) <= float(location_range_max))
        ]
                    
        

        # Prepare response data
        flightList = [{
            'id': flight.id,
            'user': flight.user_id,
            'start_time': str(flight.start_time),
            'timezone': flight.timezone,
            'country': flight.country,
            'country_code': flight.country_code,
            'location': flight.location,
            'distance': flight.distance,
            'start_lat': flight.start_lat,
            'start_long': flight.start_long,
            'start_height': flight.start_height,
            'end_height': flight.end_height,
            'duration': flight.duration,
            'timezone_raw_offset': flight.timezone_raw_offset,
            'timezone_dst_offset': flight.timezone_dst_offset,
            'public': flight.public,
            # 'igc_file': flight.igc_file,
            'igc_sum': flight.igc_sum,
            # 'kml_file': flight.kml_file,
            'uploaded': str(flight.uploaded),
            'info': flight.info
        } for flight in filtered_flights]
        
        
        if stats_enabled:
            tot_duration = 0
            for flight in flightList:
                tot_duration += flight['duration']
            return jsonify(code='0',
                           message=f'Request successfull',
                           duration=tot_duration,
                           count=len(flightList)), 200

        return jsonify(code='0', message=f'{len(flightList)} flights found', count=len(flightList), flights=flightList), 200

    except Exception as e:
        return jsonify(code='50', message=f'Error retrieving flights: {str(e)}'), 500


@app.route('/api/flights/<int:flight_id>/download', methods=['GET'])
@jwt_required()
def download_flight(flight_id):
    current_user = get_jwt_identity()
    
    filetype = request.args.get('type')
    
    if not filetype:
        return jsonify(code=10, message=f'Please select the filetype (kml or igc) as a parameter')
        

    user = User.query.get(current_user)
    
    if not user:
        return jsonify(code=30, message=f'User not found')
    
    
    flight = Flight.query.filter_by(id=flight_id).first()
    if not flight or (flight.user_id != user.id and flight.public == False):
        return jsonify(code=40, message=f'Flight {flight_id} not found or is private'), 200
    
    if filetype == "kml":
        requested_file_path = os.path.join(script_path + "/kml_files/")
        requested_filename = flight.kml_file
    elif filetype == "igc":
        requested_file_path = os.path.join(script_path + "/igc_files/")
        requested_filename = flight.igc_file
    elif filetype == "geojson":
        requested_file_path = os.path.join(script_path + "/geojson_files/")
        requested_filename = flight.geojson_file
        #tbd implement geojson
    else:
        return jsonify(code=50, message=f'Wrong type for download')
    
    if not os.path.exists(os.path.join(requested_file_path, requested_filename)):
        return jsonify(code=60, message=f'File not available')
    

    generic_filename = f'flight_{flight_id}.{filetype}'
    
    return send_from_directory(requested_file_path, requested_filename, as_attachment=True, download_name=generic_filename)


# @app.route('/api/flights/<int:flight_id>/geojson', methods=['GET'])
# @jwt_required(optional=True)
# def get_kml(flight_id):

#     current_user = get_jwt_identity()
    
#     token = request.args.get('token')
    
#     if token:
#         return jsonify(code=10, message=f'Please select the filetype (kml or igc) as a parameter')
        
#     user = User.query.get(current_user)
    
#     if not user:
#         return jsonify(code=30, message=f'User not found')
    
    
#     flight = Flight.query.filter_by(id=flight_id, user_id=user.id).first()
#     if not flight:
#         return jsonify(code=40, message=f'Flight {flight_id} not found or does not belong to the user'), 200
#     return send_from_directory(requested_file_path, requested_filename, as_attachment=True, download_name=generic_filename)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
