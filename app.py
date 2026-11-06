import sqlite3
import os
import hashlib
import hmac
import base64
import json
from flask import Flask, request

app = Flask(__name__)

db_name = "project1.db"
sql_file = "project1.sql"
db_flag = False

def json_response(data):
    return app.response_class(
        response=json.dumps(data),
        status=200,
        mimetype="application/json"
    )
def create_db():
    global db_flag
    conn = sqlite3.connect(db_name)
    try:
        with open(sql_file, "r", encoding="utf-8") as sql_startup:
            init_db = sql_startup.read()
        cursor = conn.cursor()
        cursor.executescript(init_db)
        conn.commit()
        db_flag = True
    finally:
        conn.close()
def get_db():
    global db_flag
    if not db_flag or not os.path.exists(db_name):
        create_db()
    return sqlite3.connect(db_name)

def hash_password(password, salt):
    password_with_salt = password + salt
    return hashlib.sha256(
        password_with_salt.encode("utf-8") ).hexdigest()
def valid_password(password, username, first_name, last_name):
    if len(password) < 8:
        return False
    has_uppercase = False
    has_lowercase = False
    has_number = False
    for character in password:
        if character.isupper():
            has_uppercase = True
        elif character.islower():
            has_lowercase = True
        elif character.isdigit():
            has_number = True

    if not has_uppercase or not has_lowercase or not has_number:
        return False
    password_lower = password.lower()
    if username and username.lower() in password_lower:
        return False

    if first_name and first_name.lower() in password_lower:
        return False
    if last_name and last_name.lower() in password_lower:
        return False
    return True

def get_key():
    with open("key.txt", "r", encoding="utf-8") as key_file:
        return key_file.read().strip()

def base64_encode(data):
    encoded = base64.urlsafe_b64encode(
        json.dumps(data).encode("utf-8") ).decode("utf-8")
    return encoded
def decode_base64(encoded):
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    decoded = base64.urlsafe_b64decode(
        (encoded + padding).encode("utf-8"))
    return json.loads(decoded.decode("utf-8"))

def create_jwt(username):
    header = {
        "alg": "HS256",
        "typ": "JWT"}
    payload = {
        "username": username,
        "access": "True"}
    encoded_header = base64_encode(header)
    encoded_payload = base64_encode(payload)
    message = encoded_header + "." + encoded_payload
    signature = hmac.new(
        get_key().encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256).hexdigest()
    return message + "." + signature

def verify_jwt(token):
    if not token:
        return None
    try:
        parts = token.split(".")

        if len(parts) != 3:
            return None
        encoded_header = parts[0]
        encoded_payload = parts[1]
        supplied_signature = parts[2]
        header = decode_base64(encoded_header)
        payload = decode_base64(encoded_payload)

        if header.get("alg") != "HS256":
            return None

        if header.get("typ") != "JWT":
            return None

        if payload.get("access") != "True":
            return None

        if not payload.get("username"):
            return None

        message = encoded_header + "." + encoded_payload
        expected_signature = hmac.new(
            get_key().encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(
            supplied_signature,
            expected_signature):
            return None
        return payload

    except (ValueError, TypeError, KeyError, OSError):
        return None
@app.route("/clear", methods=["GET"])
def clear():
    global db_flag
    if os.path.exists(db_name):
        os.remove(db_name)
    db_flag = False
    return json_response({"status": 1})

@app.route("/create_user", methods=["POST"])
def create_user():
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    username = request.form.get("username")
    email_address = request.form.get("email_address")
    password = request.form.get("password")
    salt = request.form.get("salt")

    if (
        first_name is None or last_name is None or username is None
        or email_address is None or password is None or salt is None
        or username == "" or email_address == "" ):
        return json_response({
            "status": 4,
            "pass_hash": "NULL"
        })

    if not valid_password(
        password, username, first_name, last_name
    ):
        return json_response({
            "status": 4,
            "pass_hash": "NULL" })
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = ?;",
            (username,)
        )

        if cursor.fetchone() is not None:
            return json_response({
                "status": 2,
                "pass_hash": "NULL"
            })
        cursor.execute(
            "SELECT id FROM users WHERE email_address = ?;",
            (email_address,)
        )

        if cursor.fetchone() is not None:
            return json_response({
                "status": 3,
                "pass_hash": "NULL"
            })

        pass_hash = hash_password(password, salt)
        cursor.execute("""
            INSERT INTO users (
                first_name,
                last_name,
                username,
                email_address,
                pass_hash,
                salt
            )
            VALUES (?, ?, ?, ?, ?, ?);
        """, (
            first_name,
            last_name,
            username,
            email_address,
            pass_hash,
            salt
        ))
        user_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO password_history (user_id, pass_hash)
            VALUES (?, ?);
        """, (user_id, pass_hash))
        conn.commit()
        return json_response({
            "status": 1,
            "pass_hash": pass_hash })
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return json_response({
            "status": 2,
            "jwt": "NULL"
        })
    conn = get_db()

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pass_hash, salt
            FROM users
            WHERE username = ?;
        """, (username,))
        user = cursor.fetchone()
        if user is None:
            return json_response({
                "status": 2,
                "jwt": "NULL"
            })
        stored_hash, salt = user
        submitted_hash = hash_password(password, salt)
        if not hmac.compare_digest(submitted_hash, stored_hash):
            return json_response({
                "status": 2,
                "jwt": "NULL"
            })

        token = create_jwt(username)
        return json_response({
            "status": 1,
            "jwt": token })

    finally:
        conn.close()

@app.route("/update", methods=["POST"])
def update():
    token = request.form.get("jwt")
    payload = verify_jwt(token)

    if payload is None:
        return json_response({"status": 3})
    token_username = payload.get("username")
    old_username = request.form.get("username")
    new_username = request.form.get("new_username")
    old_password = request.form.get("password")
    new_password = request.form.get("new_password")
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                username,
                pass_hash,
                salt,
                first_name,
                last_name
            FROM users
            WHERE username = ?;
        """, (token_username,))
        user = cursor.fetchone()
        if user is None:
            return json_response({"status": 3})

        (
            user_id,
            current_username,
            stored_hash,
            salt,
            first_name,
            last_name
        ) = user
        if old_username is not None and new_username is not None:
            if old_username != current_username:
                return json_response({"status": 2})

            if new_username == "":
                return json_response({"status": 2})

            cursor.execute("""
                SELECT id
                FROM users
                WHERE username = ? AND id != ?;
            """, (new_username, user_id))

            if cursor.fetchone() is not None:
                return json_response({"status": 2})

            cursor.execute("""
                UPDATE users
                SET username = ?
                WHERE id = ?;
            """, (new_username, user_id))

            conn.commit()

            return json_response({"status": 1})

        if old_password is not None and new_password is not None:
            old_hash = hash_password(old_password, salt)

            if not hmac.compare_digest(old_hash, stored_hash):
                return json_response({"status": 2})

            if not valid_password(
                new_password,
                current_username,
                first_name,
                last_name
            ):
                return json_response({"status": 2})

            new_hash = hash_password(new_password, salt)

            cursor.execute("""
                SELECT pass_hash
                FROM password_history
                WHERE user_id = ?;
            """, (user_id,))

            previous_hashes = cursor.fetchall()

            for previous in previous_hashes:
                if hmac.compare_digest(new_hash, previous[0]):
                    return json_response({"status": 2})

            cursor.execute("""
                UPDATE users
                SET pass_hash = ?
                WHERE id = ?;
            """, (new_hash, user_id))

            cursor.execute("""
                INSERT INTO password_history (user_id, pass_hash)
                VALUES (?, ?);
            """, (user_id, new_hash))

            conn.commit()

            return json_response({"status": 1})
        return json_response({"status": 2})
    finally:
        conn.close()


@app.route("/view", methods=["POST"])
def view():
    token = request.form.get("jwt")
    payload = verify_jwt(token)
    if payload is None:
        return json_response({
            "status": 2,
            "data": "NULL"})
    username = payload.get("username")
    conn = get_db()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username, email_address, first_name, last_name
            FROM users
            WHERE username = ?;
        """, (username,))
        user = cursor.fetchone()

        if user is None:
            return json_response({
                "status": 2,
                "data": "NULL"
            })

        data = {
            "username": user[0],
            "email_address": user[1],
            "first_name": user[2],
            "last_name": user[3]
        }
        return json_response({
            "status": 1,
            "data": data
        })
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(debug=True)