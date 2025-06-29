from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
from flask_restx import Api, Resource, fields, reqparse, Namespace
from decimal import Decimal
from flask_cors import CORS
import logging
import json
from boto3.dynamodb.conditions import Key


class JSONEncoder(json.JSONEncoder):
    """Custom encoder for Flask-RESTx to handle Decimal objects."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Check if it's an integer (e.g., Age, Number should ideally be integers)
            # Use float for potential decimal numbers, though less common for these attributes
            if obj % 1 == 0:
                return int(obj) # Convert to int if it's a whole number
            return float(obj) # Convert to float otherwise
        # Let the default encoder handle other types
        return super(JSONEncoder, self).default(obj)
    
# Helper to convert Decimal to int/float for JSON serialization
def fix_decimals(obj):
    if isinstance(obj, list):
        return [fix_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: fix_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj

logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)

app.json_encoder = JSONEncoder

# --- CORS Configuration (Place after app initialization) ---
CORS(app, supports_credentials=True, origins=[
    "http://aws-chek-free-tier-bucket.s3-website.eu-north-1.amazonaws.com", # <-- This MUST match the Origin header from browser dev tools
    "https://aws-chek-free-tier-bucket.s3-website.eu-north-1.amazonaws.com",
    "http://aws-chek-free-tier-bucket.s3.eu-north-1.amazonaws.com",
    "https://aws-chek-free-tier-bucket.s3.eu-north-1.amazonaws.com",
    "http://aws-chek-free-tier-bucket.s3.eu-north-1.amazonaws.com/GemUI",
    "https://aws-chek-free-tier-bucket.s3.eu-north-1.amazonaws.com/GemUI"
  ])

# Initialize Flask-RESTx API
# --- Add security definitions for JWT ---
authorizations = {
    'Bearer Auth': { # Define a security scheme named 'Bearer Auth'
        'type': 'apiKey', # The type of security scheme (API Key)
        'in': 'header',   # Where the key is expected (in the header)
        'name': 'Authorization', # The name of the header ('Authorization')
        'description': 'Enter your JWT token in the format "Bearer YOUR_TOKEN"' # Description for the user
    }
}
# --- End security definitions ---

api = Api(app, version='1.1', title='EPL Teams and Players API',
          description='API for managing English Premier League teams and players, and user authentication.',
          # --- Add authorizations and apply security ---
          # Define the security schemes available
          authorizations=authorizations,
          # Apply the 'Bearer Auth' scheme globally to all endpoints by default
          security='Bearer Auth',
        # --- Add tags for UI separation ---
          tags=[
              {'name': 'Session', 'description': 'User authentication related endpoints'},
              {'name': 'Users', 'description': 'Endpoints for managing user accounts'},
              {'name': 'EPL', 'description': 'Endpoints for English Premier League teams and players'}
          ]
        )

# Define a new model for the login request
login_model = api.model('UserLogin', {
    'username': fields.String(required=True, description='The username'),
    'password': fields.String(required=True, description='The user password')
})

# Define the users namespace
ns = api.namespace('users', description='User operations')
api.add_namespace(ns)

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
jwt = JWTManager(app)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')  # Change region if needed
table = dynamodb.Table('Users')  # Your DynamoDB table name

# --- Define the functional Login Resource directly under the main API instance ---
# This maps the LoginResource to the root path '/login'
@api.route('/login')
class LoginResource(Resource):
    @api.doc('user_login') # Documentation decorator for this endpoint
    @api.expect(login_model) # Link the login_model for request body documentation/validation
    def post(self):
        """Login a user and return JWT token"""
        data = request.json # Get JSON data from the request body (handled by Flask-RESTx)
        username = data.get('username')
        password = data.get('password')

        # --- Your Authentication Logic (Copy this from the old @app.route function you removed in Step 1) ---
        if username == 'vladi' and password == 'Aa111111': # This is your actual authentication logic
            access_token = create_access_token(identity=username)
            # Return the access token in the response body with 200 status
            return {'access_token': access_token}, 200
        else:
            # Return an error message with 401 Unauthorized status
            return {'message': 'Invalid username or password'}, 401
        # --- End Authentication Logic ---

# Login endpoint for user authentication
# Remove "OPTIONS" from methods here, Flask-CORS handles it automatically
# @app.route("/login", methods=["POST"])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

# # Replace with your own authentication logic
#     if username == 'vladi' and password == 'Aa111111':
#         access_token = create_access_token(identity=username)
#         return jsonify(access_token=access_token), 200
#     else:
#         return jsonify({'error': 'Invalid username or password'}), 401

# Protected endpoint to get user data
@app.route('/get_user/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user = get_jwt_identity()  # Identity of the logged-in user
    try:
        response = table.get_item(Key={'UserId': user_id})
        if 'Item' in response:
            return jsonify(response['Item']), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Retrieve all users from DynamoDB
@app.route('/users_list', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    try:
        response = table.scan()  # Retrieve all items from the table

        if 'Items' in response:
            users = response['Items']
            # 🚀 Force a test log
            logging.info("🚀 DEBUG: API is running")  # Remove flush=True here
            # Log users BEFORE sorting
            print("Users BEFORE sorting:", users)  # Remove flush=True here

            # Sorting users by UserId
            users.sort(key=lambda x: x.get('UserId', '') or 'zzz')

            # Log users AFTER sorting
            print("Users AFTER sorting:", users)  # Remove flush=True here

            return jsonify(users), 200
        else:
            return jsonify({'message': 'No users found'}), 404
    except ClientError as e:
        print("DynamoDB Error:", str(e))  # Remove flush=True here
        return jsonify({'error': str(e)}), 500


# Create a new user in DynamoDB
@app.route('/add_user', methods=['POST'])
@jwt_required()
def add_user():
    current_user = get_jwt_identity()
    data = request.get_json()

    # Validate required fields
    user_id = data.get('UserId')
    name = data.get('Name')

    if not user_id or not name:
        return jsonify({'error': 'UserId and Name are required'}), 400

    # Add default fields if they are not provided
    item = {
        'UserId': user_id,
        'Name': name,
        'Email': data.get('Email', 'unknown@example.com'),  # Default Email
        'Status': data.get('Status', 'active'),  # Default Status
        'Preferences': data.get('Preferences', {"theme": "light", "notifications": True}),  # Default Preferences
        'CreatedAt': data.get('CreatedAt', datetime.utcnow().isoformat())  # Dynamic timestamp
    }

    # Include any additional dynamic fields
    for key, value in data.items():
        if key not in item:
            item[key] = value

    try:
        table.put_item(Item=item)
        return jsonify({'message': 'User added successfully', 'user': item}), 201
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Update user data in Users table in DynamoDB
@app.route('/update_user/<user_id>', methods=['PUT'])
@jwt_required()  # Protect the endpoint with JWT authentication
def update_user(user_id):
    current_user = get_jwt_identity()  # Retrieve the identity of the currently authenticated user
    data = request.get_json()

    # Validate the input data
    if not data:
        return jsonify({'error': 'Request body is empty'}), 400

    # Construct the update expression dynamically
    update_expression = "SET "
    expression_attribute_values = {}
    for key, value in data.items():
        update_expression += f"{key} = :{key}, "
        expression_attribute_values[f":{key}"] = value

    # Remove trailing comma and space
    update_expression = update_expression.rstrip(", ")

    try:
        # Perform the update operation
        response = table.update_item(
            Key={'UserId': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW"
        )
	# Return success response with updated attributes
        updated_attributes = response.get('Attributes', {})
        if updated_attributes:
            return jsonify({
                'message': 'User updated successfully',
                'updatedAttributes': updated_attributes
            }), 200
        else:
            return jsonify({'message': 'No attributes updated'}), 200

    except ClientError as e:
        # Handle DynamoDB client errors
        error_message = e.response['Error'].get('Message', 'Unknown error')
        return jsonify({'error': error_message}), 500
    except Exception as e:
        # General exception handling
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

# Remove user by DELETE from the table
@app.route('/delete_user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    # Get the current authenticated user (optional for auditing)
    current_user = get_jwt_identity()

    try:
        # Delete the user from DynamoDB using the UserId
        response = table.delete_item(
            Key={'UserId': user_id}
        )

        # Check if the item was deleted successfully
        if 'Attributes' not in response:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': f'User {user_id} deleted successfully'}), 200
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Search users in Users table in DynamoDB
@app.route('/search_users', methods=['GET'])
@jwt_required()  # Optional: Protect the endpoint with JWT authentication
def search_users():
    current_user = get_jwt_identity()  # Retrieve the identity of the currently authenticated user (optional)
    
    # Get query parameters from the URL
    name = request.args.get('name', None)
    email = request.args.get('email', None)

    # If no parameters are provided, return an error
    if not name and not email:
        return jsonify({'error': 'At least one search parameter (name or email) must be provided'}), 400

    try:
        if name:  # Search by name
            response = table.scan(
                FilterExpression="contains(#Name, :name)",
                ExpressionAttributeNames={"#Name": "Name"},
                ExpressionAttributeValues={":name": name}
            )
        elif email:  # Search by email
            response = table.scan(
                FilterExpression="contains(#Email, :email)",
                ExpressionAttributeNames={"#Email": "Email"},
                ExpressionAttributeValues={":email": email}
            )
        else:
            # Add additional logic if searching for multiple fields at once
            pass

        # Return the matching users
        items = response.get('Items', [])
        if not items:
            return jsonify({'message': 'No users found'}), 404

        return jsonify({'message': 'Users found', 'users': items}), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

# ———                   EPL Namespace & Models —————————————————————————————————————————————
epl_ns = Namespace('epl', description='EPL team & player operations')

team_model = epl_ns.model('Team', {
    'TeamID':    fields.String(required=True, description='Team partition key'),
    'EntityType': fields.String(required=True, description="'Team' or 'Player'"),
    'TeamName':  fields.String(required=True, description='Name of the team'),
    'Stadium':   fields.String(required=False, description='Home stadium'),
    'Founded':   fields.String(required=False, description='Foundation year'),
    'Manager':   fields.String(required=False, description='Team manager')
})

player_model = epl_ns.model('Player', {
    'TeamID':     fields.String(required=True, description='Parent TeamID'),
    'EntityType': fields.String(required=True, description="'Player'"),
    'PlayerName': fields.String(required=True, description='Name of the player'),
    'Position':   fields.String(required=False, description='Playing position'),
    'Number':     fields.Integer(required=False, description='Jersey number'),
    'Age':        fields.Integer(required=False, description='Player age')
})

# DynamoDB table handle
epl_table = dynamodb.Table('EPLTeamsAndPlayers')


# ——— Endpoints ——————————————————————————————————————————————————————

# Get teams by TeamId
@epl_ns.route('/teams')
class TeamList(Resource):
    @epl_ns.doc('list_teams')
    @jwt_required()
    def get(self):
        """List all real teams (not players)"""
        try:
            resp = epl_table.scan(
                FilterExpression="EntityType = :t",
                ExpressionAttributeValues={':t': 'TEAM'}
            )
            items = resp.get('Items', [])
            return fix_decimals(items), 200
        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500
        
# Get Teams details & players with filtering       

@epl_ns.route('/teams/<string:team_id>/details')
class TeamWithPlayers(Resource):
    @epl_ns.doc(params={
        'position': 'Filter by player position',
        'min_age': 'Minimum player age',
        'max_age': 'Maximum player age',
        'number': 'Filter by jersey number',
        'sort_by': 'Field to sort by (age, number, PlayerName, Position)',
        'order': 'asc or desc (default is asc)'
    })
    @jwt_required()
    def get(self, team_id):
        """Get full team info with filters and sorting"""
        try:
            team_resp = epl_table.get_item(Key={
                'TeamID': team_id,
                'EntityType': 'TEAM'
            })
            team = team_resp.get('Item')
            if not team:
                return {'error': f'Team {team_id} not found'}, 404

            players_resp = epl_table.scan(
                FilterExpression="TeamID = :t AND begins_with(EntityType, :p)",
                ExpressionAttributeValues={':t': team_id, ':p': 'PLAYER#'}
            )
            players = players_resp.get('Items', [])

            # Query params
            position = request.args.get('position')
            min_age = request.args.get('min_age', type=int)
            max_age = request.args.get('max_age', type=int)
            number = request.args.get('number', type=int)
            sort_by = request.args.get('sort_by')
            order = request.args.get('order', 'asc').lower()

            # Filter players
            filtered = []
            for player in players:
                if position and player.get('Position') != position:
                    continue
                if min_age is not None and int(player.get('Age', 0)) < min_age:
                    continue
                if max_age is not None and int(player.get('Age', 0)) > max_age:
                    continue
                if number is not None and int(player.get('Number', -1)) != number:
                    continue
                filtered.append(player)

            # Sort players
            if sort_by:
                reverse = (order == 'desc')
                try:
                    filtered.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)
                except Exception as e:
                    return {'error': f'Invalid sort_by field: {sort_by}'}, 400

            return fix_decimals({
                'team': team,
                'players': filtered
            }), 200

        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500

# Add Team 
@epl_ns.route('/teams')
class AddTeam(Resource):
    @epl_ns.expect(team_model)
    @epl_ns.doc('create_team')
    @jwt_required()
    def post(self):
        """Add a new team"""
        team = epl_ns.payload.copy()
        try:
            epl_table.put_item(Item=team)
            return {'message': 'Team created', 'team': team}, 201
        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500



@epl_ns.route('/teams/<string:team_id>')
class TeamPlayers(Resource):
    @jwt_required()
    def get(self, team_id):
        """Get all players from a specific team"""
        try:
            resp = epl_table.scan(
                FilterExpression="TeamID = :t AND contains(EntityType, :p)",
                ExpressionAttributeValues={':t': team_id, ':p': 'PLAYER#'}
            )
            players = resp.get('Items', [])
            return {
                'team_id': team_id,
                'players': fix_decimals(players)
            }, 200
        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500
        
    @epl_ns.expect(team_model)
    @epl_ns.doc('update_team')
    @jwt_required()
    def put(self, team_id):
        """Update team attributes"""
        data = epl_ns.payload
        expr = []
        vals = {}
        for k, v in data.items():
            if k != 'TeamID':
                expr.append(f"{k} = :{k}")
                vals[f":{k}"] = v
        update_expr = "SET " + ", ".join(expr)
        try:
            resp = epl_table.update_item(
                Key={'TeamID': team_id},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=vals,
                ReturnValues="UPDATED_NEW"
            )
            return {'updated': resp.get('Attributes', {})}, 200
        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500

@epl_ns.route('/teams/<string:team_id>')
class TeamResource(Resource):
    @epl_ns.doc('delete_team')
    @jwt_required()
    def delete(self, team_id):
        """
        Delete a team and all its players from DynamoDB.
        """
        try:
            # 1. Delete all players for the team
            player_items = epl_table.query(
                KeyConditionExpression=Key('TeamID').eq(team_id) & Key('EntityType').begins_with('PLAYER#')
            ).get('Items', [])

            with epl_table.batch_writer() as batch:
                for item in player_items:
                    batch.delete_item(Key={
                        'TeamID': item['TeamID'],
                        'EntityType': item['EntityType']
                    })

            # 2. Delete the team entry
            team_item = epl_table.get_item(
                Key={
                    'TeamID': team_id,
                    'EntityType': 'TEAM'
                }
            ).get('Item')

            if team_item:
                epl_table.delete_item(
                    Key={
                        'TeamID': team_id,
                        'EntityType': 'TEAM'
                    }
                )
            else:
                return {'message': f'Team {team_id} not found.'}, 404

            return {'message': f'Team {team_id} and all players deleted'}, 200

        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500



@epl_ns.route('/players')
class PlayerAdd(Resource):
    @epl_ns.expect(player_model)
    @epl_ns.doc('add_player')
    @jwt_required()
    def post(self):
        """Add a new player"""
        player = epl_ns.payload.copy()
        try:
            epl_table.put_item(Item=player)
            return {'message': 'Player added', 'player': player}, 201
        except ClientError as e:
            return {'error': e.response['Error']['Message']}, 500


# --- Update Player and Delete Player Resource (Corrected Route and Key) ---

@epl_ns.route('/players/<string:team_id>/<int:jersey_number>')
class PlayerResource(Resource):
    # Inside the PlayerResource class
    @epl_ns.doc('update_player')
    @epl_ns.expect(player_model) # Keep expect for body validation/docs
    @jwt_required()
    # <-- Corrected method signature to get jersey_number from the path -->
    def put(self, team_id, jersey_number):
        """Update a player's info by Team ID and Jersey Number"""
        data = epl_ns.payload # Data from the request body
        expr_parts = []
        vals = {}
        expression_attribute_names = {}

        # Build the update expression for attributes from the body
        for k, v in data.items():
            # Exclude key attributes (TeamID, EntityType) from the update expression
            if k not in ('TeamID', 'EntityType'):
                attr_name_placeholder = f"#{k}"
                val_placeholder = f":{k}"
                expr_parts.append(f"{attr_name_placeholder} = {val_placeholder}")
                vals[val_placeholder] = v
                expression_attribute_names[attr_name_placeholder] = k

        update_expression = "SET " + ", ".join(expr_parts) if expr_parts else ""

        if not update_expression:
             # Handle case where body is empty or only contains key attributes
             return {'message': 'No updateable fields provided in the request body'}, 400


        try:
            # --- FIX: Construct the correct DynamoDB Key using TeamID (PK) and EntityType (SK) ---
            # Use the team_id from the URL and the jersey_number from the URL
            db_key = {'TeamID': team_id, 'EntityType': f'PLAYER#{jersey_number}'}
            # --- End FIX ---

            # Perform the update operation using the correct key
            resp = epl_table.update_item(
                Key=db_key, # Use the correctly constructed key
                UpdateExpression=update_expression,
                ExpressionAttributeValues=vals,
                ExpressionAttributeNames=expression_attribute_names, # Include ExpressionAttributeNames
                ReturnValues="UPDATED_NEW" # We want the updated attributes
            )
            updated_attrs = resp.get('Attributes', {})
            # --- FIX: Apply fix_decimals to the updated attributes before returning ---
            return {'message': 'Player updated successfully', 'updatedAttributes': fix_decimals(updated_attrs)}, 200
            # --- End FIX ---

        except ClientError as e:
            logging.error(f"DynamoDB ClientError updating player {team_id}/{jersey_number}: {e}", exc_info=True)
            error_message = e.response.get('Error', {}).get('Message', 'An unknown DynamoDB error occurred.')
            return {'error': error_message}, e.response['ResponseMetadata']['HTTPStatusCode']
        except Exception as e:
             logging.error(f"Unexpected error updating player {team_id}/{jersey_number}: {e}", exc_info=True)
             return {'error': f'An unexpected server error occurred: {str(e)}'}, 500

    # Delete method code below ...


    @epl_ns.doc('delete_player')
    @jwt_required()
    # <-- Corrected method signature to get jersey_number from the path -->
    def delete(self, team_id, jersey_number):
        """Delete a specific player by Team ID and Jersey Number"""
        try:
            # --- FIX: Construct the correct DynamoDB Key for delete ---
            # Use the team_id from the URL and the jersey_number from the URL
            db_key = {'TeamID': team_id, 'EntityType': f'PLAYER#{jersey_number}'}
            # --- End FIX ---

            # Perform the delete operation using the correct key
            epl_table.delete_item(Key=db_key)
            return {'message': f'Player with number {jersey_number} deleted from team {team_id}'}, 200

        except ClientError as e:
             logging.error(f"DynamoDB ClientError deleting player {team_id}/{jersey_number}: {e}", exc_info=True)
             error_message = e.response.get('Error', {}).get('Message', 'An unknown DynamoDB error occurred.')
             return {'error': error_message}, e.response['ResponseMetadata']['HTTPStatusCode']
        except Exception as e:
             logging.error(f"Unexpected error deleting player {team_id}/{jersey_number}: {e}", exc_info=True)
             return {'error': f'An unexpected server error occurred: {str(e)}'}, 500

# --- End of Corrected Player Resource ---


@epl_ns.route('/search')
class EPLSearch(Resource):
    @epl_ns.doc('search_epl')
    @epl_ns.param('key', 'Attribute name to search')
    @epl_ns.param('value', 'Value to match') # Updated description
    @jwt_required()
    def get(self):
        """Search teams or players by any attribute"""
        key   = request.args.get('key')
        value = request.args.get('value')

        if not key or not value:
            return {'error': 'key and value query params required'}, 400

        # Define placeholder names and values
        expression_attribute_names = {f"#{key}": key}
        expression_attribute_values = {':v': value}
        filter_expression = ""

        # --- Conditional FilterExpression based on attribute key type ---
        # Assuming 'Number' and 'Age' are numeric attributes
        if key in ['Number', 'Age']:
            # For numeric attributes, use equality check
            try:
                # Attempt to convert the value to the appropriate type (integer)
                # This assumes Age and Number are stored as integers
                num_value = int(value)
                expression_attribute_values = {':v': num_value}
                filter_expression = f"#{key} = :v" # Use equality
            except ValueError:
                 return {'error': f'Value for numeric search key "{key}" must be an integer'}, 400
        else:
            # For other (presumably string) attributes, use 'contains'
             filter_expression = f"contains(#{key}, :v)"
        # --- End of Conditional FilterExpression ---

        try:
            resp = epl_table.scan(
                FilterExpression=filter_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )

            items = resp.get('Items', [])
            return {'results': fix_decimals(items)}, 200

        except ClientError as e:
            logging.error(f"DynamoDB ClientError during search: {e}", exc_info=True)
            error_message = e.response.get('Error', {}).get('Message', 'An unknown DynamoDB error occurred.')
            # Return 400 if it's an InvalidArgumentException or validation error from DynamoDB
            if e.response['Error']['Code'] in ['ValidationException', 'InvalidArgumentException']:
                 return {'error': error_message}, 400
            return {'error': error_message}, e.response['ResponseMetadata']['HTTPStatusCode']
        except Exception as e:
             logging.error(f"Unexpected server error during search: {e}", exc_info=True)
             return {'error': f'An unexpected server error occurred: {str(e)}'}, 500




# =======================================Swagger=========================================== #
# ==== Namespace Configuration ====
session_ns = Namespace('Session', description="Session management")
users_ns = Namespace('Users', description='User management')

# Attach endpoints to namespace
## session_ns.add_resource(UserLogin, '/login')


# Define models for request/response validation and documentation
user_model = api.model('User', {
    'UserId': fields.String(required=True, description='The user ID'),
    'Name': fields.String(required=True, description='The user name'),
    'Email': fields.String(required=False, description='The user email', default='unknown@example.com'),
    'Status': fields.String(required=False, description='The user status', default='active'),
    'Preferences': fields.Raw(required=False, description='The user preferences', default={"theme": "light", "notifications": True}),
    'CreatedAt': fields.String(required=False, description='The user creation timestamp', default=datetime.utcnow().isoformat())
})


update_user_model = api.model('UpdateUser', {
    'UserName': fields.String(required=False, description='The user name'),
    'Email': fields.String(required=False, description='The user email'),
    'Phone': fields.String(required=False, description='The user phone'),
    'Address': fields.String(required=False, description='The user address'),
    'Status': fields.String(required=False, description='The user status')
})



# Define a new model for searching users
search_user_model = api.model('Search_User', {
    'name': fields.String(required=False, description='The name to search for'),
    'email': fields.String(required=False, description='The email to search for')
})

# Mock DynamoDB table (replace with actual table logic)
mock_table = {}

# # Login Endpoint for Swagger
# @session_ns.route('/login')
# class UserLogin(Resource):
#     @api.expect(login_model)
#     def post(self):
#         """Login a user"""
#         data = request.json
#         username = data.get ('username')
#         password = data.get ('password')
#         # Logic for login (you can validate the user here, e.g., check user credentials)
#         if username == "vladi" and password == "Aa111111":
#             return jsonify({"message": "Login successful", "user": username}), 200
#         else:
#             return jsonify({"message": "Invalid credentials"}), 400

#         return {'message': 'Login successful'}

# Define Swagger endpoints

    # Get user by Id
@ns.route('/<string:user_id>')
@ns.param('user_id', 'The user identifier')
class UserResource(Resource):
    @ns.doc('get_user')
    @ns.response(200, 'Success')
    @ns.response(404, 'User not found')
    def get(self, user_id):
        """Fetch a user by ID"""
        user = mock_table.get(user_id)
        if not user:
            api.abort(404, f"User {user_id} not found")
        return jsonify(user)
    # Update user Endpoint
    @ns.doc('update_user')
    @ns.expect(update_user_model)
    @ns.response(200, 'User updated successfully')
    @ns.response(400, 'Bad request')
    def put(self, user_id):
        """Update a user by ID"""
        if user_id not in mock_table:
            api.abort(404, f"User {user_id} not found")

        # Update user with provided fields
        data = request.json
        for key, value in data.items():
            mock_table[user_id][key] = value
        return jsonify({"message": "User updated successfully", "updatedUser": mock_table[user_id]})

    # List of all users endpoint
@users_ns.route('/users_list')
class UserList(Resource):
    @ns.doc('users_list')
    def get(self):
        """List all users"""
        # Make sure you retrieve the users from DynamoDB instead of the mock_table
        try:
            response = table.scan()  # Retrieve all items from the table
            if 'Items' in response:
                users = response['Items']
                users.sort(key=lambda x: x.get('UserId', '') or 'zzz')
                return jsonify(users), 200
            else:
                return jsonify({'message': 'No users found'}), 404
        except ClientError as e:
            return jsonify({'error': str(e)}), 500

    
    # Add user endpoint
@users_ns.route('/add_user')
class UserAdd(Resource):
    @ns.doc('add_user')
    @ns.expect(user_model)  # Swagger model for request validation
    @ns.response(201, 'User created successfully')
    @ns.response(400, 'Missing required fields')
    def post(self):
        """Create a new user"""
        data = request.json

        # Validate required fields
        user_id = data.get('UserId')
        name = data.get('Name')

        if not user_id or not name:
            return jsonify({'error': 'UserId and Name are required'}), 400

        # Add default fields if they are not provided
        item = {
            'UserId': user_id,
            'Name': name,
            'Email': data.get('Email', 'unknown@example.com'),  # Default Email
            'Status': data.get('Status', 'active'),  # Default Status
            'Preferences': data.get('Preferences', {"theme": "light", "notifications": True}),  # Default Preferences
            'CreatedAt': data.get('CreatedAt', datetime.utcnow().isoformat())  # Dynamic timestamp
        }

        # Include any additional dynamic fields
        for key, value in data.items():
            if key not in item:
                item[key] = value

        # Simulate DynamoDB insert here
        # table.put_item(Item=item)  # Uncomment this line for actual DynamoDB interaction

        # For Swagger, just mock the response as if the user is successfully created
        return jsonify({'message': 'User added successfully', 'user': item}), 201


    # Add Delete User Endpoint
@ns.route('/delete_user/<user_id>')
class DeleteUser(Resource):
    @ns.doc('delete_user')
    @ns.response(200, 'User deleted successfully')
    @ns.response(404, 'User not found')
    def delete(self, user_id):
        """Delete a user by ID"""
        if user_id in mock_table:
            del mock_table[user_id]
            return {'message': 'User deleted successfully'}
        else:
            api.abort(404, f"User {user_id} not found")

    # Add Search User Endpoint
@ns.route('/search_users')
class UserSearch(Resource):
    @ns.doc('search_users')
    @ns.expect(search_user_model)
    @ns.response(200, 'Users found')
    @ns.response(400, 'Bad request')
    @ns.response(404, 'No users found')
    def get(self):
        """Search users by name or email"""
        name = request.args.get('name', None)
        email = request.args.get('email', None)

        if not name and not email:
            return {'error': 'At least one search parameter (name or email) must be provided'}, 400

        try:
            if name:
                response = table.scan(
                    FilterExpression="contains(#Name, :name)",
                    ExpressionAttributeNames={"#Name": "Name"},
                    ExpressionAttributeValues={":name": name}
                )
            elif email:
                response = table.scan(
                    FilterExpression="contains(#Email, :email)",
                    ExpressionAttributeNames={"#Email": "Email"},
                    ExpressionAttributeValues={":email": email}
                )
            items = response.get('Items', [])
            if not items:
                return {'message': 'No users found'}, 404

            return {'message': 'Users found', 'users': items}, 200

        except ClientError as e:
            return {'error': str(e)}, 500
        except Exception as e:
            return {'error': f'An unexpected error occurred: {str(e)}'}, 500
        

# Register the session namespace with the API
api.add_namespace(session_ns)
api.add_namespace(users_ns)  # This will make the `/users` path available in Swagger
api.add_namespace(epl_ns)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Run the Flask app
