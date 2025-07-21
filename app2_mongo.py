from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from datetime import datetime
from flask_restx import Api, Resource, fields, Namespace
from decimal import Decimal
from flask_cors import CORS
import logging
import json
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId  # Import ObjectId for JSONEncoder

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class JSONEncoder(json.JSONEncoder):
    """Custom encoder for Flask-RESTx to handle Decimal and ObjectId objects."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        if isinstance(obj, ObjectId):  # Correctly handle MongoDB ObjectId
            return str(obj)
        return super(JSONEncoder, self).default(obj)


# Helper to convert Decimal to int/float for JSON serialization (still useful if Decimal objects are passed around)
def fix_decimals(obj):
    if isinstance(obj, list):
        return [fix_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: fix_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    # Also handle ObjectId if it somehow slips through before JSONEncoder (less likely with direct returns)
    elif isinstance(obj, ObjectId):
        return str(obj)
    return obj


# Initialize Flask app
app = Flask(__name__)
app.json_encoder = JSONEncoder  # Use custom JSON encoder

# --- CORS Configuration ---
CORS(app, supports_credentials=True, origins=["https://epl-api-ui.onrender.com"])

# Initialize Flask-RESTx API
authorizations = {
    "Bearer Auth": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": 'Enter your JWT token in the format "Bearer YOUR_TOKEN"',
    }
}

api = Api(
    app,
    version="1.1",
    title="EPL Teams and Players API",
    description="API for managing English Premier League teams and players, and user authentication.",
    authorizations=authorizations,
    security="Bearer Auth",
    tags=[
        {"name": "Session", "description": "User authentication related endpoints"},
        {"name": "Users", "description": "Endpoints for managing user accounts"},
        {
            "name": "EPL",
            "description": "Endpoints for English Premier League teams and players",
        },
    ],
)

# JWT configuration
app.config["JWT_SECRET_KEY"] = (
    "your-secret-key"  # Use a strong, unique key in production
)
jwt = JWTManager(app)

# --- MongoDB Connection ---
# MongoDB connection URL
MONGO_URI = "mongodb+srv://chekvld:P92fRLNGIGPNkky7@flaskapicluster.jiu62vv.mongodb.net/?retryWrites=true&w=majority&appName=FlaskAPICluster"
try:
    client = MongoClient(MONGO_URI)
    db = client.EPL_25_26  # Your database name
    users_collection = db.users  # Collection for users
    epl_collection = (
        db.epl_teams_players
    )  # Collection for EPL teams and players (now stores teams with embedded players)
    logging.info("Successfully connected to MongoDB Atlas!")
except PyMongoError as e:
    logging.error(f"Error connecting to MongoDB: {e}")
    # Consider handling this more gracefully in a production app, e.g., exiting or showing maintenance page

# Define a new model for the login request
login_model = api.model(
    "UserLogin",
    {
        "username": fields.String(required=True, description="The username"),
        "password": fields.String(required=True, description="The user password"),
    },
)

# Define the users namespace
users_ns = api.namespace("users", description="User operations")
api.add_namespace(users_ns)


# --- Define the functional Login Resource directly under the main API instance ---
@api.route("/login")
class LoginResource(Resource):
    @api.doc("user_login")
    @api.expect(login_model)
    def post(self):
        """Login a user and return JWT token"""
        data = request.json
        username = data.get("username")
        password = data.get("password")

        # Hardcoded authentication for demonstration.
        # In a real app, you would query the 'users_collection' to validate credentials.
        if username == "vladi" and password == "Aa111111":
            access_token = create_access_token(identity=username)
            return {"access_token": access_token}, 200
        else:
            return {"message": "Invalid username or password"}, 401


# --- User Endpoints (Adapted for MongoDB) ---


@app.route("/get_user/<user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to access user ID '{user_id}'")
    try:
        user = users_collection.find_one({"_id": user_id})  # Use _id for primary key
        if user:
            user["UserId"] = user.pop("_id")  # Restore UserId for consistency if needed
            return jsonify(fix_decimals(user)), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/users_list", methods=["GET"])
@jwt_required()
def get_all_users():
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to list all users")
    try:
        users = list(users_collection.find({}))  # Get all users
        # Convert _id to UserId and then remove _id
        for user in users:
            user["UserId"] = user.pop("_id")

        users.sort(key=lambda x: x.get("UserId", "") or "zzz")  # Sort in Python

        logging.info("Users BEFORE serialization: %s", users)
        return jsonify(fix_decimals(users)), 200
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/add_user", methods=["POST"])
@jwt_required()
def add_user():
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to add a new user")
    data = request.get_json()

    user_id = data.get("UserId")
    name = data.get("Name")

    if not user_id or not name:
        return jsonify({"error": "UserId and Name are required"}), 400

    # Prepare item for MongoDB, mapping UserId to _id
    item = {
        "_id": user_id,  # Use UserId as _id
        "Name": name,
        "Email": data.get("Email", "unknown@example.com"),
        "Status": data.get("Status", "active"),
        "Preferences": data.get(
            "Preferences", {"theme": "light", "notifications": True}
        ),
        "CreatedAt": data.get("CreatedAt", datetime.utcnow().isoformat()),
    }

    # Include any additional dynamic fields, ensuring they don't overwrite _id
    for key, value in data.items():
        if key not in item and key != "UserId":  # Ensure UserId isn't re-added
            item[key] = value

    try:
        users_collection.insert_one(item)
        item["UserId"] = item.pop("_id")  # Restore UserId for response
        return (
            jsonify({"message": "User added successfully", "user": fix_decimals(item)}),
            201,
        )
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        # Handle duplicate key error specifically
        if e.code == 11000:  # DuplicateKeyError
            return (
                jsonify({"error": f"User with UserId '{user_id}' already exists."}),
                409,
            )
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/update_user/<user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to update user ID '{user_id}'")
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is empty"}), 400

    # Remove UserId if present in data, as _id is immutable in MongoDB
    if "UserId" in data:
        data.pop("UserId")

    try:
        # MongoDB update expects a dictionary for $set
        update_result = users_collection.update_one({"_id": user_id}, {"$set": data})

        if update_result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404
        if update_result.modified_count == 0:
            return (
                jsonify({"message": "No attributes updated or user data is the same"}),
                200,
            )

        # Retrieve the updated document to return it
        updated_user = users_collection.find_one({"_id": user_id})
        updated_user["UserId"] = updated_user.pop(
            "_id"
        )  # Restore UserId for consistency
        return (
            jsonify(
                {
                    "message": "User updated successfully",
                    "updatedAttributes": fix_decimals(updated_user),
                }
            ),
            200,
        )
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/delete_user/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to delete user ID '{user_id}'")
    try:
        delete_result = users_collection.delete_one({"_id": user_id})
        if delete_result.deleted_count == 0:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"message": f"User {user_id} deleted successfully"}), 200
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/search_users", methods=["GET"])
@jwt_required()
def search_users():
    current_user = (
        get_jwt_identity()
    )  # Retrieve the identity of the currently authenticated user
    logging.info(f"User '{current_user}' attempting to search users")
    name = request.args.get("name", None)
    email = request.args.get("email", None)

    if not name and not email:
        return (
            jsonify(
                {
                    "error": "At least one search parameter (name or email) must be provided"
                }
            ),
            400,
        )

    query = {}
    if name:
        query["Name"] = {
            "$regex": name,
            "$options": "i",
        }  # Case-insensitive partial match
    elif email:
        query["Email"] = {
            "$regex": email,
            "$options": "i",
        }  # Case-insensitive partial match

    try:
        items = list(users_collection.find(query))
        if not items:
            return jsonify({"message": "No users found"}), 404

        for item in items:
            item["UserId"] = item.pop("_id")  # Restore UserId for consistency

        return jsonify({"message": "Users found", "users": fix_decimals(items)}), 200
    except PyMongoError as e:
        logging.error(f"MongoDB Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


# ——— EPL Namespace & Models —————————————————————————————————————————————
epl_ns = Namespace("epl", description="EPL team & player operations")
api.add_namespace(epl_ns)  # Add epl_ns to the main API instance

# Team model for adding/updating teams (does not include Players array in model for direct input)
team_model = epl_ns.model(
    "Team",
    {
        "TeamID": fields.String(required=True, description="Team unique identifier"),
        "TeamName": fields.String(required=True, description="Name of the team"),
        "Stadium": fields.String(required=False, description="Home stadium"),
        "Founded": fields.String(required=False, description="Foundation year"),
        "Manager": fields.String(required=False, description="Team manager"),
    },
)

# Player model for adding/updating players (as they would be nested)
player_model = epl_ns.model(
    "Player",
    {
        "PlayerID": fields.String(
            required=True, description="Player unique identifier within team"
        ),  # Added PlayerID as per user JSON
        "PlayerName": fields.String(required=True, description="Name of the player"),
        "Position": fields.String(required=False, description="Playing position"),
        "Number": fields.Integer(required=False, description="Jersey number"),
        "Age": fields.Integer(required=False, description="Player age"),
    },
)

# --- EPL Endpoints (Adapted for MongoDB - Nested Players) ————————————————————————————————————

# ---------------------- Teams Endpoints ----------------------


@epl_ns.route("/teams")
class TeamList(Resource):
    @epl_ns.doc("list_teams")
    @jwt_required()
    def get(self):
        """List all teams (documents with embedded players)"""
        current_user = get_jwt_identity()
        logging.info(f"User '{current_user}' attempting to list all teams")
        try:
            # Fetch all documents from the collection
            teams = list(
                epl_collection.find({})
            )  # Now fetching all documents as they are teams with players

            for team in teams:
                # Convert ObjectId to string
                team["id"] = str(team.pop("_id"))
                # No change to players array itself, it's already structured

            return fix_decimals(teams), 200
        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@epl_ns.route("/teams/<string:team_id>/details")
class TeamWithPlayers(Resource):
    @epl_ns.doc(
        params={
            "position": "Filter by player position",
            "min_age": "Minimum player age",
            "max_age": "Maximum player age",
            "number": "Filter by jersey number",
            "sort_by": "Field to sort by (age, number, PlayerName, Position)",
            "order": "asc or desc (default is asc)",
        }
    )
    @jwt_required()
    def get(self, team_id):
        """Get full team info with filtered and sorted players"""
        current_user = get_jwt_identity()
        logging.info(
            f"User '{current_user}' attempting to get details for team ID '{team_id}'"
        )
        try:
            team = epl_collection.find_one(
                {"TeamID": team_id}
            )  # Find the team document
            if not team:
                return {"error": f"Team {team_id} not found"}, 404

            team["id"] = str(team.pop("_id"))  # Convert team's _id

            players = team.get("Players", [])  # Get the embedded players list

            # Query params for filtering players
            position = request.args.get("position")
            min_age = request.args.get("min_age", type=int)
            max_age = request.args.get("max_age", type=int)
            number = request.args.get("number", type=int)
            sort_by = request.args.get("sort_by")
            order = request.args.get("order", "asc").lower()

            # Filter players (in-memory after fetching)
            filtered = []
            for player in players:
                if position and player.get("Position") != position:
                    continue
                if min_age is not None and player.get("Age", 0) < min_age:
                    continue
                if max_age is not None and player.get("Age", 0) > max_age:
                    continue
                if number is not None and player.get("Number", -1) != number:
                    continue
                filtered.append(player)

            # Sort players (in-memory)
            if sort_by:
                reverse = order == "desc"
                try:
                    if sort_by in ["Age", "Number"]:
                        filtered.sort(
                            key=lambda x: (
                                x.get(sort_by, 0) if x.get(sort_by) is not None else -1
                            ),
                            reverse=reverse,
                        )
                    else:
                        filtered.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)
                except Exception as e:
                    return {
                        "error": f"Invalid sort_by field or data type for sorting: {sort_by} - {e}"
                    }, 400

            return fix_decimals({"team": team, "players": filtered}), 200

        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@epl_ns.route("/teams")
class AddTeam(Resource):
    @epl_ns.expect(team_model)
    @epl_ns.doc("create_team")
    @jwt_required()
    def post(self):
        """Add a new team (with an empty Players array)"""
        current_user = get_jwt_identity()
        logging.info(f"User '{current_user}' attempting to add a new team")
        team_data = epl_ns.payload.copy()

        # Check if TeamID already exists
        if epl_collection.find_one({"TeamID": team_data.get("TeamID")}):
            return {
                "message": f"Team with TeamID '{team_data.get('TeamID')}' already exists."
            }, 409

        # Initialize Players array
        team_data["Players"] = []

        try:
            result = epl_collection.insert_one(team_data)
            team_data["id"] = str(
                result.inserted_id
            )  # Add MongoDB's _id to the response
            return {"message": "Team created", "team": fix_decimals(team_data)}, 201
        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@epl_ns.route("/teams/<string:team_id>")
class TeamPlayers(Resource):
    @jwt_required()
    def get(self, team_id):
        """Get all players from a specific team"""
        current_user = get_jwt_identity()
        logging.info(
            f"User '{current_user}' attempting to get players for team ID '{team_id}'"
        )
        try:
            team = epl_collection.find_one({"TeamID": team_id})
            if not team:
                return {"error": f"Team {team_id} not found"}, 404

            players = team.get("Players", [])

            return {"team_id": team_id, "players": fix_decimals(players)}, 200
        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500

    @epl_ns.expect(team_model)
    @epl_ns.doc("update_team")
    @jwt_required()
    def put(self, team_id):
        """Update team attributes (excluding players)"""
        current_user = get_jwt_identity()
        logging.info(f"User '{current_user}' attempting to update team ID '{team_id}'")
        data = epl_ns.payload
        # Remove TeamID from update data if present, as it's part of the key
        data.pop("TeamID", None)
        # Ensure we don't accidentally overwrite the Players array with an empty one if not intended
        data.pop("Players", None)

        if not data:
            return {"message": "No updateable fields provided"}, 400

        try:
            update_result = epl_collection.update_one(
                {"TeamID": team_id},  # Filter for the specific team
                {"$set": data},  # Set the new values
            )

            if update_result.matched_count == 0:
                return {"error": f"Team {team_id} not found"}, 404
            if update_result.modified_count == 0:
                return {
                    "message": "No attributes updated or team data is the same"
                }, 200

            updated_team = epl_collection.find_one({"TeamID": team_id})
            if updated_team:
                updated_team["id"] = str(updated_team.pop("_id"))
                return {
                    "message": "Team updated successfully",
                    "updated": fix_decimals(updated_team),
                }, 200
            else:
                return {"error": "Failed to retrieve updated team"}, 500

        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@epl_ns.route("/teams/<string:team_id>")
class TeamResource(Resource):
    @epl_ns.doc("delete_team")
    @jwt_required()
    def delete(self, team_id):
        """
        Delete a team and all its embedded players from MongoDB.
        """
        current_user = get_jwt_identity()
        logging.info(f"User '{current_user}' attempting to delete team ID '{team_id}'")
        try:
            # Delete the team document (which automatically deletes embedded players)
            delete_result = epl_collection.delete_one({"TeamID": team_id})
            logging.info(
                f"Deleted {delete_result.deleted_count} team document for team {team_id}"
            )

            if delete_result.deleted_count == 0:
                return {"message": f"Team {team_id} not found."}, 404

            return {"message": f"Team {team_id} and all its players deleted"}, 200

        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


# ======================== Players Endpoints ========================


@epl_ns.route("/players")
class PlayerAdd(Resource):
    @epl_ns.expect(player_model)
    @epl_ns.doc("add_player")
    @epl_ns.param("team_id", "The TeamID to add the player to", required=True)
    @jwt_required()
    def post(self):
        """Add a new player to an existing team's Players array"""
        current_user = get_jwt_identity()
        logging.info(f"User '{current_user}' attempting to add a new player")
        player_data = epl_ns.payload.copy()
        team_id = request.args.get("team_id")

        if not team_id:
            return {"error": "team_id query parameter is required to add a player"}, 400

        # Check if the team exists
        team = epl_collection.find_one({"TeamID": team_id})
        if not team:
            return {"error": f"Team {team_id} not found. Cannot add player."}, 404

        # Check if player with the same PlayerID already exists in this team's Players array
        existing_player = epl_collection.find_one(
            {"TeamID": team_id, "Players.PlayerID": player_data.get("PlayerID")}
        )
        if existing_player:
            return {
                "message": f"Player with PlayerID '{player_data.get('PlayerID')}' already exists in team '{team_id}'"
            }, 409

        try:
            # Use $push to add the new player to the 'Players' array
            update_result = epl_collection.update_one(
                {"TeamID": team_id}, {"$push": {"Players": player_data}}
            )

            if update_result.modified_count == 0:
                return {"error": "Failed to add player to team"}, 500

            return {
                "message": "Player added to team",
                "player": fix_decimals(player_data),
            }, 201
        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@app.route("/epl/transfer_player", methods=["POST"])
def transfer_player():
    data = request.json
    from_team = data.get("from_team_id")
    to_team = data.get("to_team_id")
    player_id = data.get("player_id")
    new_player_id = data.get("new_player_id") or player_id
    new_number = data.get("new_number")

    if not from_team or not to_team or not player_id:
        return (
            jsonify({"error": "from_team_id, to_team_id, and player_id are required"}),
            400,
        )

    # Get source team
    from_team_doc = epl_collection.find_one({"TeamID": from_team})
    if not from_team_doc:
        return jsonify({"error": f"Team '{from_team}' not found"}), 404

    # Find player
    player = next(
        (p for p in from_team_doc.get("Players", []) if p.get("PlayerID") == player_id),
        None,
    )
    if not player:
        return (
            jsonify({"error": f"Player '{player_id}' not found in team '{from_team}'"}),
            404,
        )

    # Remove player from source team
    epl_collection.update_one(
        {"TeamID": from_team}, {"$pull": {"Players": {"PlayerID": player_id}}}
    )

    # Update player fields
    player["PlayerID"] = new_player_id
    if new_number is not None:
        player["Number"] = new_number

    # Add player to destination team
    result = epl_collection.update_one(
        {"TeamID": to_team}, {"$push": {"Players": player}}
    )

    if result.matched_count == 0:
        # Rollback if to_team not found
        epl_collection.update_one({"TeamID": from_team}, {"$push": {"Players": player}})
        return (
            jsonify(
                {"error": f"Target team '{to_team}' not found. Transfer rolled back."}
            ),
            404,
        )

    return (
        jsonify(
            {
                "message": f"Player '{player_id}' transferred from '{from_team}' to '{to_team}'",
                "new_player_id": new_player_id,
                "new_number": new_number,
            }
        ),
        200,
    )


@epl_ns.route(
    "/players/<string:team_id>/<string:player_id>"
)  # Changed to player_id instead of jersey_number
class PlayerResource(Resource):
    @epl_ns.doc("update_player")
    @epl_ns.expect(player_model)
    @jwt_required()
    def put(self, team_id, player_id):
        """Update a player's info by Team ID and Player ID"""
        current_user = get_jwt_identity()
        logging.info(
            f"User '{current_user}' attempting to update player '{player_id}' for team ID '{team_id}'"
        )
        data = epl_ns.payload
        # Remove PlayerID from payload as it's used for query, not update field
        data.pop("PlayerID", None)

        if not data:
            return {"message": "No updateable fields provided in the request body"}, 400

        try:
            # Use arrayFilters to update a specific element in the Players array
            update_result = epl_collection.update_one(
                {
                    "TeamID": team_id,
                    "Players.PlayerID": player_id,
                },  # Find the team document and a matching player
                {
                    "$set": {f"Players.$.{k}": v for k, v in data.items()}
                },  # Update fields in the matched player
            )

            if update_result.matched_count == 0:
                return {"error": "Team or Player not found"}, 404
            if update_result.modified_count == 0:
                return {
                    "message": "No attributes updated or player data is the same"
                }, 200

            # Retrieve the updated document to return the updated player
            team_doc = epl_collection.find_one({"TeamID": team_id})
            updated_player = next(
                (
                    p
                    for p in team_doc.get("Players", [])
                    if p.get("PlayerID") == player_id
                ),
                None,
            )

            if updated_player:
                return {
                    "message": "Player updated successfully",
                    "updatedAttributes": fix_decimals(updated_player),
                }, 200
            else:
                return {
                    "error": "Failed to retrieve updated player (after successful update)"
                }, 500

        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500

    @epl_ns.doc("delete_player")
    @jwt_required()
    def delete(self, team_id, player_id):
        """Delete a specific player by Team ID and Player ID"""
        current_user = get_jwt_identity()
        logging.info(
            f"User '{current_user}' attempting to delete player '{player_id}' for team ID '{team_id}'"
        )
        try:
            # Use $pull to remove the player object from the 'Players' array
            update_result = epl_collection.update_one(
                {"TeamID": team_id}, {"$pull": {"Players": {"PlayerID": player_id}}}
            )

            if update_result.modified_count == 0:
                return {
                    "error": "Team or Player not found, or player already deleted"
                }, 404

            return {
                "message": f"Player with PlayerID {player_id} deleted from team {team_id}"
            }, 200
        except PyMongoError as e:
            logging.error(f"MongoDB Error: {e}", exc_info=True)
            return {"error": str(e)}, 500
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {str(e)}"}, 500


from flask import Flask, jsonify, request  # Make sure jsonify is imported at the top

# ... (your existing code)

from flask import (
    Flask,
    jsonify,
    request,
)  # 'jsonify' is not strictly needed for this specific return anymore, but keep it if used elsewhere.


@epl_ns.route("/search")
class EPLSearch(Resource):
    @epl_ns.doc("search_epl")
    @epl_ns.param(
        "key",
        "Attribute to search (e.g., TeamName, Stadium, Players.PlayerName, Players.Age)",
    )
    @epl_ns.param("value", "Value to match for the given key")
    @jwt_required()
    def get(self):
        """
        Search for teams and players.
        - For team-level searches (e.g., TeamName), it filters teams.
        - For player-level searches (e.g., Players.Age), it filters teams AND
          the players within those teams to show only matching players.
        """
        current_user = get_jwt_identity()
        key = request.args.get("key")
        value = request.args.get("value")

        logging.info(
            f"User '{current_user}' initiated search with key='{key}', value='{value}'"
        )

        if not key or not value:
            return {
                "error": "Both 'key' and 'value' query parameters are required"
            }, 400

        try:
            items = []
            # Handle search on top-level team fields (e.g., TeamName, Stadium)
            if not key.startswith("Players."):
                query_filter = {key: {"$regex": value, "$options": "i"}}
                logging.info(f"Constructed simple find query: {query_filter}")
                items = list(epl_collection.find(query_filter))

            # Handle search on nested player fields (e.g., Players.Age) using an Aggregation Pipeline
            else:
                player_field = key.split(".", 1)[1]  # e.g., 'Age' or 'PlayerName'

                pipeline = [
                    # Stage 1: Find teams that have at least one player matching the criteria.
                    {"$match": {}},
                    # Stage 2: Filter the 'Players' array to include ONLY matching players.
                    {
                        "$addFields": {
                            "Players": {
                                "$filter": {
                                    "input": "$Players",
                                    "as": "player",
                                    "cond": {},
                                }
                            }
                        }
                    },
                    # Stage 3: Remove teams from the result if their 'Players' array became empty after filtering.
                    {"$match": {"Players": {"$ne": []}}},
                ]

                # Dynamically build the condition for the initial match (Stage 1) and the array filter (Stage 2)
                if player_field in ["Age", "Number"]:
                    try:
                        numeric_value = int(value)
                        pipeline[0]["$match"][key] = numeric_value
                        pipeline[1]["$addFields"]["Players"]["$filter"]["cond"] = {
                            "$eq": [f"$$player.{player_field}", numeric_value]
                        }
                    except ValueError:
                        return {
                            "error": f"Value for numeric key '{key}' must be an integer."
                        }, 400
                else:  # For string fields like PlayerName or Position
                    regex_condition = {"$regex": value, "$options": "i"}
                    pipeline[0]["$match"][key] = regex_condition
                    # $regexMatch is used for filtering arrays by regex (requires MongoDB 4.2+)
                    pipeline[1]["$addFields"]["Players"]["$filter"]["cond"] = {
                        "$regexMatch": {
                            "input": f"$$player.{player_field}",
                            "regex": value,
                            "options": "i",
                        }
                    }

                logging.info(
                    f"Constructed aggregation pipeline: {json.dumps(pipeline)}"
                )
                items = list(epl_collection.aggregate(pipeline))

            # --- Common response processing for both search types ---
            if not items:
                return {
                    "message": "No results found matching your criteria",
                    "results": [],
                }, 200

            for item in items:
                item["id"] = str(item.pop("_id"))

            return {"results": fix_decimals(items)}, 200

        except PyMongoError as e:
            logging.error(f"MongoDB Error during search: {e}", exc_info=True)
            return {"error": f"Database error: {str(e)}"}, 500
        except Exception as e:
            logging.error(
                f"An unexpected error occurred during search: {e}", exc_info=True
            )
            return {"error": f"An unexpected server error occurred: {str(e)}"}, 500


# =======================================Swagger Models and Namespaces (pointing to actual MongoDB logic) =========================================== #

session_ns = Namespace("Session", description="Session management")
api.add_namespace(session_ns)

user_model = api.model(
    "User",
    {
        "UserId": fields.String(
            required=True, description="The user ID (will be MongoDB _id)"
        ),
        "Name": fields.String(required=True, description="The user name"),
        "Email": fields.String(
            required=False, description="The user email", default="unknown@example.com"
        ),
        "Status": fields.String(
            required=False, description="The user status", default="active"
        ),
        "Preferences": fields.Raw(
            required=False,
            description="The user preferences",
            default={"theme": "light", "notifications": True},
        ),
        "CreatedAt": fields.String(
            required=False, description="The user creation timestamp"
        ),
    },
)

update_user_model = api.model(
    "UpdateUser",
    {
        "Name": fields.String(required=False, description="The user name"),
        "Email": fields.String(required=False, description="The user email"),
        "Phone": fields.String(required=False, description="The user phone"),
        "Address": fields.String(required=False, description="The user address"),
        "Status": fields.String(required=False, description="The user status"),
    },
)

search_user_model = api.model(
    "Search_User",
    {
        "name": fields.String(required=False, description="The name to search for"),
        "email": fields.String(required=False, description="The email to search for"),
    },
)


# Define Swagger endpoints pointing to existing Flask routes
# Get user by Id
@users_ns.route("/<string:user_id>")
@users_ns.param("user_id", "The user identifier")
class SwaggerUserResource(Resource):
    @users_ns.doc("get_user")
    @users_ns.response(200, "Success", user_model)
    @users_ns.response(404, "User not found")
    def get(self, user_id):
        """Fetch a user by ID"""
        response, status_code = get_user(user_id)
        return response, status_code

    # Update user Endpoint
    @users_ns.doc("update_user")
    @users_ns.expect(update_user_model)
    @users_ns.response(200, "User updated successfully", user_model)
    @users_ns.response(400, "Bad request")
    @users_ns.response(404, "User not found")
    def put(self, user_id):
        """Update a user by ID"""
        response, status_code = update_user(user_id)
        return response, status_code


# List of all users endpoint
@users_ns.route("/users_list")
class SwaggerUserList(Resource):
    @users_ns.doc("users_list")
    @users_ns.response(200, "Success", [user_model])
    @users_ns.response(404, "No users found")
    def get(self):
        """List all users"""
        response, status_code = get_all_users()
        return response, status_code


# Add user endpoint
@users_ns.route("/add_user")
class SwaggerUserAdd(Resource):
    @users_ns.doc("add_user")
    @users_ns.expect(user_model)
    @users_ns.response(201, "User created successfully", user_model)
    @users_ns.response(400, "Missing required fields")
    @users_ns.response(409, "User already exists")
    def post(self):
        """Create a new user"""
        response, status_code = add_user()
        return response, status_code


# Delete User Endpoint
@users_ns.route("/delete_user/<user_id>")
class SwaggerDeleteUser(Resource):
    @users_ns.doc("delete_user")
    @users_ns.response(200, "User deleted successfully")
    @users_ns.response(404, "User not found")
    def delete(self, user_id):
        """Delete a user by ID"""
        response, status_code = delete_user(user_id)
        return response, status_code


# Search User Endpoint
@users_ns.route("/search_users")
class SwaggerUserSearch(Resource):
    @users_ns.doc("search_users")
    @users_ns.expect(search_user_model)
    @users_ns.response(
        200,
        "Users found",
        api.model(
            "UserSearchResult",
            {"message": fields.String, "users": fields.List(fields.Nested(user_model))},
        ),
    )
    @users_ns.response(400, "Bad request")
    @users_ns.response(404, "No users found")
    def get(self):
        """Search users by name or email"""
        response, status_code = search_users()
        return response, status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
