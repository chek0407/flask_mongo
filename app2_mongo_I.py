from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_restx import Api, Resource, fields
from pymongo import MongoClient
import bcrypt
import uuid
import os
from datetime import timedelta

app = Flask(__name__)
CORS(app)

# JWT Config
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# MongoDB Config
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
db = client["EPL"]
users_collection = db["Users"]
teams_collection = db["Teams"]
players_collection = db["Players"]

# Swagger setup
api = Api(app, version='1.0', title='EPL API', description='EPL and User Management API')

auth_ns = api.namespace('auth', description='Authentication operations')
users_ns = api.namespace('users', description='User operations')
epl_ns = api.namespace('epl', description='Team and Player operations')

# Swagger models
user_model = api.model('User', {
    'UserId': fields.String,
    'Name': fields.String,
    'Email': fields.String,
    'Password': fields.String
})

team_model = api.model('Team', {
    'TeamID': fields.String,
    'TeamName': fields.String,
    'Stadium': fields.String,
    'Founded': fields.String,
    'Manager': fields.String,
    'Age': fields.Integer,
    'EntityType': fields.String
})

player_model = api.model('Player', {
    'PlayerID': fields.String,
    'PlayerName': fields.String,
    'Position': fields.String,
    'Number': fields.Integer,
    'Age': fields.Integer,
    'TeamID': fields.String,
    'EntityType': fields.String
})

@auth_ns.route('/login')
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = users_collection.find_one({'Email': data['Email']})
        if user and bcrypt.checkpw(data['Password'].encode('utf-8'), user['Password']):
            token = create_access_token(identity=user['UserId'])
            return {'access_token': token}, 200
        return {'message': 'Invalid credentials'}, 401

@users_ns.route('/get_user/<string:user_id>')
class GetUser(Resource):
    @jwt_required()
    def get(self, user_id):
        user = users_collection.find_one({'UserId': user_id}, {'_id': 0, 'Password': 0})
        if not user:
            return {'message': 'User not found'}, 404
        return jsonify(user)

@users_ns.route('/users_list')
class UsersList(Resource):
    @jwt_required()
    def get(self):
        users = list(users_collection.find({}, {'_id': 0, 'Password': 0}))
        return jsonify(users)

@users_ns.route('/add_user')
class AddUser(Resource):
    @jwt_required()
    @users_ns.expect(user_model)
    def post(self):
        data = request.get_json()
        if users_collection.find_one({'UserId': data['UserId']}):
            return {'message': 'User already exists'}, 400
        data['Password'] = bcrypt.hashpw(data['Password'].encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one(data)
        return {'message': 'User added'}, 201

@users_ns.route('/update_user/<string:user_id>')
class UpdateUser(Resource):
    @jwt_required()
    def put(self, user_id):
        data = request.get_json()
        if 'Password' in data:
            data['Password'] = bcrypt.hashpw(data['Password'].encode('utf-8'), bcrypt.gensalt())
        result = users_collection.update_one({'UserId': user_id}, {'$set': data})
        if result.modified_count:
            return {'message': 'User updated'}, 200
        return {'message': 'User not found or no change'}, 404

@users_ns.route('/delete_user/<string:user_id>')
class DeleteUser(Resource):
    @jwt_required()
    def delete(self, user_id):
        result = users_collection.delete_one({'UserId': user_id})
        if result.deleted_count:
            return {'message': 'User deleted'}, 200
        return {'message': 'User not found'}, 404

@users_ns.route('/search_users')
class SearchUsers(Resource):
    @jwt_required()
    def get(self):
        key = request.args.get('key')
        value = request.args.get('value')
        if not key or not value:
            return {'message': 'Missing key or value'}, 400
        results = list(users_collection.find({key: value}, {'_id': 0, 'Password': 0}))
        return jsonify(results)

@epl_ns.route('/teams')
class TeamList(Resource):
    def get(self):
        teams = list(teams_collection.find({}, {'_id': 0}))
        return jsonify(teams)

@epl_ns.route('/add_team')
class AddTeam(Resource):
    @jwt_required()
    @epl_ns.expect(team_model)
    def post(self):
        data = request.get_json()
        if teams_collection.find_one({'TeamID': data['TeamID']}):
            return {'message': 'Team already exists'}, 400
        teams_collection.insert_one(data)
        return {'message': 'Team added'}, 201

@epl_ns.route('/update_team/<string:team_id>')
class UpdateTeam(Resource):
    @jwt_required()
    def put(self, team_id):
        data = request.get_json()
        result = teams_collection.update_one({'TeamID': team_id}, {'$set': data})
        if result.modified_count:
            return {'message': 'Team updated'}, 200
        return {'message': 'Team not found or no change'}, 404

@epl_ns.route('/delete_team/<string:team_id>')
class DeleteTeam(Resource):
    @jwt_required()
    def delete(self, team_id):
        result = teams_collection.delete_one({'TeamID': team_id})
        if result.deleted_count:
            return {'message': 'Team deleted'}, 200
        return {'message': 'Team not found'}, 404

@epl_ns.route('/teams/<string:team_id>/details')
class TeamDetails(Resource):
    def get(self, team_id):
        players = list(players_collection.find({'TeamID': team_id}, {'_id': 0}))
        return jsonify(players)

@epl_ns.route('/add_player')
class AddPlayer(Resource):
    @jwt_required()
    @epl_ns.expect(player_model)
    def post(self):
        data = request.get_json()
        if players_collection.find_one({'PlayerID': data['PlayerID'], 'TeamID': data['TeamID']}):
            return {'message': 'Player already exists in team'}, 400
        players_collection.insert_one(data)
        return {'message': 'Player added'}, 201

@epl_ns.route('/update_player/<string:team_id>/<string:player_id>')
class UpdatePlayer(Resource):
    @jwt_required()
    def put(self, team_id, player_id):
        data = request.get_json()
        result = players_collection.update_one(
            {'TeamID': team_id, 'PlayerID': player_id},
            {'$set': data}
        )
        if result.modified_count:
            return {'message': 'Player updated'}, 200
        return {'message': 'Player not found or no change'}, 404

@epl_ns.route('/delete_player/<string:team_id>/<string:player_id>')
class DeletePlayer(Resource):
    @jwt_required()
    def delete(self, team_id, player_id):
        result = players_collection.delete_one({'TeamID': team_id, 'PlayerID': player_id})
        if result.deleted_count:
            return {'message': 'Player deleted'}, 200
        return {'message': 'Player not found'}, 404

@epl_ns.route('/players_list')
class PlayerList(Resource):
    def get(self):
        players = list(players_collection.find({}, {'_id': 0}))
        return jsonify(players)

@epl_ns.route('/search')
class SearchPlayer(Resource):
    def get(self):
        key = request.args.get('key')
        value = request.args.get('value')
        if not key or not value:
            return {'message': 'Missing key or value'}, 400
        query = {key: value}
        results = list(players_collection.find(query, {'_id': 0}))
        return jsonify(results)

# Health check (for monitoring)
@api.route('/health')
class Health(Resource):
    def get(self):
        return {'status': 'OK'}, 200

# Register namespaces
api.add_namespace(auth_ns, path='/auth')
api.add_namespace(users_ns, path='/users')
api.add_namespace(epl_ns, path='/epl')

# Start the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
