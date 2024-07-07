import os
import sys
import tempfile
import pytest
import jwt
from datetime import datetime
from sqlalchemy.exc import IntegrityError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app, db, User

@pytest.fixture
def client():
    db_fd, temp_db = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + temp_db
    app.config['TESTING'] = True

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

    os.close(db_fd)
    os.unlink(temp_db)


# Testing for new user registration
def register(client, firstName, lastName, email, password, phone):
    return client.post("/auth/register", json={
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "password": password,
        "phone": phone
    })


def login(client, email, password):
    return client.post('/auth/login', json={
        "email": email,
        "password": password
    })


def test_login(client):
    response = login(client, "tester@gmail.com", "password")
    if response.status_code != 200:
        print(response.get_json())
    assert response.status_code == 200
    assert b"Login successful" in response.data


def test_register(client):
    response = register(client, "Gideon", "Fregene", "gideon@gmail.com", "password", "1234567890")
    if response.status_code != 201:
        # print(response.get_json())
        response_data = response.get_json()
        if "errors" in response_data:
            for error in response_data["errors"]:
                if error["message"] == "User already exists.":
                    assert response.status_code == 422
                    assert "User already exists." in response.data.decode('utf-8')
                    return
    else:
        assert response.status_code == 201
        assert b"Registration successful" in response.data
        # assert b"Organisation created upon registration." in response.data


def test_database_constraints():
    # Use Flask app context for database operations
    with app.app_context():
        # Create a user instance to insert into the database
        user = User(
            firstName="John",
            lastName="Doe",
            email="john.doe@example.com",
            password="hashed_password",  # Replace with actual hashed password
            phone="1234567890"
        )

        # Add the user to the session (but don't commit)
        db.session.add(user)

        try:
            # Attempt to commit the user to the database
            db.session.commit()
        except IntegrityError as e:
            # Assert the expected database constraint violation
            assert "NOT NULL constraint failed" in str(
                e.orig), f"Expected UNIQUE constraint violation, got: {str(e.orig)}"
        finally:
            # Rollback the session to ensure clean state for next tests
            db.session.rollback()


def test_token_expiry(client):
    response = login(client, "tester@gmail.com", "password")
    if response.status_code != 200:
        print(response.get_json())
    assert response.status_code == 200
    assert b"Login successful" in response.data
    # Extracting the token from response data
    token = response.json["data"]["accessToken"]

    # Decoding the token to ascertain its validity
    decoded_token = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])

    # assert "exp" in decoded_token

    # Verifying the expiration time
    exp_timestamp = decoded_token["exp"]
    exp_datetime = datetime.utcfromtimestamp(exp_timestamp)
    assert exp_datetime > datetime.utcnow()


if __name__ == '__main__':
    pytest.main()
