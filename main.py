from flask import Flask, request, jsonify
from flask_login import login_user, current_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from models import User, Organisation, db
from flask_migrate import Migrate
import jwt
from datetime import datetime, timedelta
from functools import wraps
import re
from dotenv import load_dotenv
import os
import psycopg2

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default_secret_key")  # Use a default for local development
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///authen.db")


db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('accessToken')
        if not token:
            return jsonify({"status": "Bad request",
                            "message": "Token is missing",
                            "statusCode": 400}), 400
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(userId=data["userId"]).first()
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "Bad request",
                            "message": "Token has expired",
                            "statusCode": 422}), 422
        except jwt.InvalidTokenError:
            return jsonify({"status": "Bad request",
                            "message": "Invalid token",
                            "statusCode": 422}), 422
        kwargs['current_user'] = current_user
        return f(*args, **kwargs)

    return decorated


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    greeting = {
        "Message": "Welcome home"
    }
    return jsonify("response", greeting)


@app.route("/auth/register", methods=["POST"])
def registration():
    data = request.get_json()
    if not data:
        return jsonify({"message": 'No input data provided'}), 422

    errors = []
    required_fields = ['firstName', 'lastName', 'email', 'password']

    # Check for required fields and their specific validations
    for field in required_fields:
        if not data.get(field):
            errors.append({
                "field": field,
                "message": "{} is required. You must provide it for validation.".format(field)
            })
        else:
            # Field-specific validations
            if field in ['firstName', 'lastName'] and not data[field].isalpha():
                errors.append({
                    "field": field,
                    "message": "{} must contain only alphabets.".format(field)
                })
            if field == 'email' and not re.match(r'^[\w.-]+@[\w.-]+\.\w+$', data[field]):
                errors.append({
                    "field": "email",
                    "message": "You must provide a valid email."
                })
            if field == 'password' and len(data[field]) < 5:
                errors.append({
                    "field": "password",
                    "message": "Password must be at least 5 characters long."
                })
            if len(data[field]) > 255:
                errors.append({
                    "field": field,
                    "message": "{} input must not be too long.".format(field)
                })

    if errors:
        return jsonify({"errors": errors}), 422

    firstName = data.get('firstName')
    lastName = data.get('lastName')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    user_exists = User.query.filter_by(email=email).first()
    if user_exists:
        return jsonify({"errors": [
            {
                "field": "email",
                "message": "User already exists."
            }
        ]}), 422

    passwd_hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
    user_id = str(uuid.uuid4())

    new_user = User(
        userId=user_id,
        firstName=firstName,
        lastName=lastName,
        email=email,
        password=passwd_hashed,
        phone=phone
    )

    try:
        db.session.add(new_user)
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "Bad request",
                        "message": str(e),
                        "statusCode": 422}), 422
    org_name = "{}'s Organisation".format(firstName)

    # Creating a new organisation.
    new_org = Organisation(
        orgId=str(uuid.uuid4()),
        name=org_name,
        description="Organisation created upon registration.",
        creator_id=new_user.id
    )
    # Add organisation to the database
    try:
        db.session.add(new_org)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "Bad request",
            "message": "Registration unsuccessful",
            "statusCode": 400
        }), 400
    token = jwt.encode({"userId": user_id, 'exp': datetime.utcnow() + timedelta(hours=1)},
                       app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "status": "success",
        "message": "Registration successful",
        "data": {
            "accessToken": token,
            "user": {
                "userId": user_id,
                "firstName": firstName,
                "lastName": lastName,
                "email": email,
                "phone": phone
            }
        }
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    if request.method == "POST":
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "Bad request",
                "message": "No data provided",
                "statusCode": 401
            }), 401

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({
                "status": "Bad request",
                "message": "Email or password not provided",
                "statusCode": 401
            }), 401

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                "status": "Bad request",
                "message": "No user found",
                "statusCode": 401
            }), 401

        if check_password_hash(user.password, password):
            token = jwt.encode({
                'userId': user.userId,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config["SECRET_KEY"], algorithm="HS256")

            login_user(user)
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "data": {
                    "accessToken": token,
                    "user": {
                        "userId": user.userId,
                        "firstName": user.firstName,
                        "lastName": user.lastName,
                        "email": user.email,
                        "phone": user.phone
                    }
                }
            }), 200

        return jsonify({
            "status": "Bad request.",
            "message": "Authentication failed",
            "statusCode": 401
        }), 401


@app.route('/api/users/<userId>')
@token_required
def get_user(userId):
    if not current_user.userId:
        return jsonify({"status": "Bad request",
                        "message": "Access denied",
                        "statusCode": 401}), 401
    user = User.query.filter_by(userId=userId).first()
    if not user:
        return jsonify({"status": "Bad request",
                        "message": "Access denied",
                        "statusCode": 401}), 401
    user_data = {"userId": user.userId,
                 "firstName": user.firstName,
                 "lastName": user.lastName,
                 "email": user.email,
                 "phone": user.phone
                 }
    return jsonify({"status": "success",
                    "message": "Here is your record.",
                    "data": user_data
                    }), 200


@app.route("/api/organisations")
@token_required
def organisation(**kwargs):
    current_user = kwargs.get('current_user')
    if not current_user.is_authenticated:
        return jsonify({"status": "Bad request",
                        "message": "Access denied",
                        "statusCode": 401}), 401
    user_orgs = Organisation.query.filter_by(creator_id=current_user.id).all()
    orgs_data = []
    for org in user_orgs:
        orgs_data.append([{
            "orgId": org.orgId,
            "name": org.name,
            "description": org.description
        }])
    return jsonify({
        "status": "success",
        "message": "Organisations retrieved successfully!",
        "data": orgs_data
    })


@app.route('/api/organisations/<orgId>')
@token_required
def fetch_org(orgId, current_user):
    if not current_user.is_authenticated:
        return jsonify({"status": "Bad Request",
                        "message": "Client error",
                        "statusCode": 400}), 400
    org = Organisation.query.filter_by(orgId=orgId).first()
    if not org:
        return jsonify({"status": "success",
                        "message": "You don't have any organisation!",
                        "statusCode": 200}), 200

    return jsonify({
        "status": "success",
        "message": "Record found.",
        "data": {
            "orgId": org.orgId,
            "name": org.name,
            "description": org.description
        }
    })



@app.route('/api/organisations', methods=["POST"])
@token_required
def create_org(current_user):
    if not current_user.is_authenticated:
        return jsonify({"status": "Bad Request",
                        "message": "Client error",
                        "statusCode": 400}), 400
    data = request.get_json()
    if not data:
        return jsonify({"status": "Bad Request",
                        "message": "You did not provide any data",
                        "statusCode": 400}), 400
    name = data['name']
    description = data['description']

    if not name:
        return jsonify({
            "status": "Bad request",
            "message": "Name required.",
            "statusCode": 422
        }), 422
    new_org = Organisation(orgId=str(uuid.uuid4()), name="{}'s Organisation".format(name), description=description, creator_id=current_user.id)
    try:
        db.session.add(new_org)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Organisation created successfully.",
            "data": {
                "orgId": new_org.orgId,
                "name": new_org.name,
                "description": new_org.description
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "Bad request",
            "message": str(e),
            "statusCode": 500
        }), 500


@app.route('/api/organisations/<orgId>/users', methods=["POST"])
@token_required
def join_org(current_user, orgId):
    if not current_user.is_authenticated:
        return jsonify({
            "status": "Bad request",
            "message": "Unauthorised",
            "statusCode": 422
        }), 422
    organisation = Organisation.query.filter_by(orgId=orgId).first()
    if not organisation:
        return jsonify({
            "status": "Bad request",
            "message": "Such organisation does not exit.",
            "statusCode": 422
        }), 422
    if organisation in current_user.organisations_joined:
        return jsonify({
            "status": "Bad request",
            "message": "User is already a member of this organisation.",
            "statusCode": 400
        }), 400

    current_user.organisations_joined.append(organisation)
    try:
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "User added to organisation successfully"
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "Bad request",
            "message": str(e),
            "statusCode": 422
        }), 422


if __name__ == "__main__":
    app.run(debug=True)
