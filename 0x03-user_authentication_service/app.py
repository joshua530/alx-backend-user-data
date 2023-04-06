#!/usr/bin/env python3
""" Main application module
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth
from typing import Union

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def home() -> str:
    """ Serves home page
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """
    creates new user session
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    res = jsonify({"email": email, "message": "logged in"})
    res.set_cookie('session_id', session_id)
    return res


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> tuple:
    """ updates user password
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def reset_password() -> tuple:
    """ resets user password
    """
    email = request.form.get('email')
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email,
                        "reset_token": token}), 200
    except ValueError:
        abort(403)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    destroys user session

    403 error is returned if session is invalid or does not exist
    """
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect(url_for('home'))


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user() -> Union[str, tuple]:
    """ Serves user regisration route
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> tuple:
    """
    fetches user's profile from session details
    """
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
