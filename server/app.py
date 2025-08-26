from flask import request, session
from flask_restful import Resource
from config import app, db, api
from models import User, UserSchema


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "Username and password are required"}, 422

        if User.query.filter_by(username=username).first():
            return {"error": "Username already taken"}, 422

        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        session["user_id"] = user.id

        return UserSchema().dump(user), 201


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if not user or not user.authenticate(password):
            return {"error": "Invalid credentials"}, 401

        session["user_id"] = user.id
        return UserSchema().dump(user), 200


class Logout(Resource):
    def delete(self):
        session.pop("user_id", None)
        return "", 204


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return "", 204

        user = db.session.get(User, user_id)
        if not user:
            return "", 204

        return UserSchema().dump(user), 200


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")


if __name__ == "__main__":
    app.run(port=5555, debug=True)