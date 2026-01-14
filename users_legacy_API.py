# user_legacy_api.py

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from pymongo.errors import PyMongoError
from datetime import datetime
import logging

from app2_mongo import users_collection


@jwt_required()
def get_user(user_id):


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