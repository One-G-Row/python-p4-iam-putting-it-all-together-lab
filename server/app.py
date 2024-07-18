#!/usr/bin/env python3
from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


@app.before_request
def check_if_logged_in():
    open_access_list = ['signup', 'login', 'check_session']
    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        data = request.json

        username = data.get('username')
        image_url = data.get('image_url')
        bio = data.get('bio')
        password = data.get('password')

        if not username or not password:
            return {'error': 'Username and password required'}, 422

        try:
            user = User(username=username, password_hash=password, image_url=image_url, bio=bio)
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': '422 Unprocessable Entity'}), 422
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 422
        

class CheckSession(Resource):
    def get(self):
         user_id = session.get('user_id')
         if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }), 200
         return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        return {'error': 'Invalid username or password'}, 401
  

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None) 
        return '', 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': "Unauthorized"}, 401

        recipes = Recipe.query.all()
        recipes_data = [
            {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            } for recipe in recipes
        ]

        return jsonify(recipes=recipes_data), 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': "Unauthorized"}, 401

        data = request.json
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or len(instructions) < 50:
            return {'error':"Invalid data"}, 422
        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()

            recipe_data = {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
            }
        }

            return jsonify(recipe_data), 201

        except IntegrityError:
            db.session.rollback()
            return {'error': '422 Unprocessable Entity'}, 422 

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
