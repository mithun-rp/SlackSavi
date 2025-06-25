from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, make_response, request, Response, jsonify, session
from slackeventsapi import SlackEventAdapter
import requests
import threading
import json
import logging
import time

# Global token and expiry time
SESSION = {
    "token": None,
    "expires_at": 0  # Epoch time in seconds
}

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# Initialize Flask app
app = Flask(__name__)

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Slack Events Adapter
slack_events_adapter = SlackEventAdapter(
    os.environ.get('SLACK_SIGNING_SECRET'),
    '/slack/events',
    app
)

# Initialize Slack Client
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
client = WebClient(token=SLACK_BOT_TOKEN)
BOT_ID = client.auth_test()["user_id"]

# Saviynt API Configuration
SAVIYNT_BASE_URL = os.getenv("SAVIYNT_API_URL")
LOGIN_URL = f"{SAVIYNT_BASE_URL}/ECM/api/login"
GET_USER_URL = f"{SAVIYNT_BASE_URL}/ECM/api/v5/getUser"
PENDING_APPROVALS_URL = f"{SAVIYNT_BASE_URL}/ECM/api/v5/getPendingApprovals"
GET_SAVROLES_URL = f"{SAVIYNT_BASE_URL}/ECM/api/v5/getSavRoles"

# Store Slack user sessions
user_sessions = {}  # Format: {user_id: {"token": token, "expires_at": timestamp}}

# ============================ API HELPERS ============================


def call_saviynt_api(url, token, payload=None, method='POST'):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-API-Version": "5",
        # Optional client ID
        "X-Client-Id": os.getenv("SAVIYNT_CLIENT_ID", "")
    }

    try:
        if method == 'GET':
            # For GET requests, send parameters as query string
            response = requests.get(
                url,
                headers=headers,
                params=payload,  # This sends parameters as query string
                timeout=15
            )
        else:
            # For POST requests, send payload as JSON body
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=15
            )

        if response.status_code != 200:
            logger.error(
                f"API Error {response.status_code}: {response.text[:500]}")
            return {
                "errorCode": response.status_code,
                "msg": response.text[:500]
            }

        return response.json()

    except Exception as e:
        logger.error(f"API request exception: {str(e)}")
        return {"errorCode": "REQUEST_FAILED", "msg": str(e)}

# ============================ SAVIYNT LOGIN ============================


def saviynt_login(username, password):
    payload = {
        "username": username,
        "password": password,
        "scope": "read:users read:approvals read:roles"
    }
    try:
        logger.info(f"Calling Saviynt login for {username}")
        resp = requests.post(LOGIN_URL, json=payload, timeout=15)
        logger.info(
            f"Saviynt login HTTP {resp.status_code} – Response text: {resp.text}")

        # Check for successful response
        if resp.status_code != 200:
            error_msg = f"Login failed with status {resp.status_code}: {resp.text[:200]}"
            logger.error(error_msg)
            return None, error_msg

        data = resp.json()
        token = data.get("access_token")
        expires_in = data.get("expires_in", 3600)  # Default to 1 hour

        if not token:
            logger.error("Saviynt login: No access_token in response")
            return None, "Login failed: No access token received"

        return token, expires_in, None

    except Exception as e:
        logger.error(f"Saviynt login exception: {str(e)}")
        return None, None, str(e)

# ============================ TOKEN VALIDATION ============================


def is_valid_token(token):
    """Simplified token validation"""
    return bool(token and len(token) > 50)


def get_valid_token(user_id):
    """Get valid token for user"""
    session_data = user_sessions.get(user_id)
    if not session_data:
        return None

    if time.time() < session_data["expires_at"] - 60:
        return session_data["token"]
    return None

# ============================ USER SESSION MANAGEMENT ============================


def save_user_session(user_id, token, expires_in):
    """Save user session with expiration time"""
    user_sessions[user_id] = {
        "token": token,
        "expires_at": time.time() + expires_in
    }

# ============================ SLASH COMMAND ============================


@app.route('/savi-login', methods=['POST'])
def handle_login_command():
    data = request.form
    trigger_id = data.get('trigger_id')
    channel_id = data.get('channel_id')

    client.views_open(
        trigger_id=trigger_id,
        view={
            "type": "modal",
            "callback_id": "login_modal",
            "private_metadata": json.dumps({"channel_id": channel_id}),
            "title": {"type": "plain_text", "text": "Saviynt Login"},
            "submit": {"type": "plain_text", "text": "Login"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": "username_block",
                    "element": {"type": "plain_text_input", "action_id": "username_input"},
                    "label": {"type": "plain_text", "text": "Username"}
                },
                {
                    "type": "input",
                    "block_id": "password_block",
                    "element": {"type": "plain_text_input", "action_id": "password_input"},
                    "label": {"type": "plain_text", "text": "Password"}
                }
            ]
        }
    )
    return Response(), 200

# ============================ INTERACTIVITY HANDLER ============================


@app.route('/interactivity', methods=['POST'])
def handle_interactivity():
    try:
        payload = json.loads(request.form.get('payload'))
        interaction_type = payload.get("type")

        if interaction_type == "view_submission":
            callback_id = payload['view']['callback_id']
            if callback_id == "login_modal":
                return handle_login_submission(payload)
            elif callback_id == "user_lookup_modal":
                return handle_user_lookup_submission(payload)
            elif callback_id == "pending_approvals_modal":
                return handle_pending_approvals_submission(payload)
            else:
                logger.warning(
                    f"Unhandled interaction type: {interaction_type}")
                return make_response("", 200)

        elif interaction_type == "block_actions":
            return handle_block_actions(payload)

        # Always return a valid response
        return make_response("", 200)

    except Exception as e:
        logger.exception(f"Error handling interactivity: {e}")
        return make_response(jsonify({"error": str(e)}), 500)


# ============================ RESPONSE FORMATTERS ============================


def format_user_info(user):
    # Extract important fields or use 'N/A' if missing
    fields = [
        {"title": "Display Name", "value": user.get("displayname")},
        {"title": "Email", "value": user.get("email")},
        {"title": "Status", "value": user.get("status")},
        {"title": "Created Date", "value": user.get("createddate")},
        {"title": "Last Login", "value": user.get("lastlogindate")},
        {"title": "User ID", "value": user.get("userid")},
        {"title": "First Name", "value": user.get("firstname")},
        {"title": "Last Name", "value": user.get("lastname")},
        {"title": "Location",
            "value": f"{user.get('city')}, {user.get('state')}, {user.get('country')}"}
    ]

    # Create blocks with proper formatting
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"User: {user.get('username', 'N/A')}"
            }
        },
        {
            "type": "divider"
        }
    ]

    # Add fields in pairs
    field_blocks = []
    for i in range(0, len(fields), 2):
        pair = fields[i:i+2]
        field_text = ""
        for field in pair:
            field_text += f"*{field['title']}:*\n{field['value'] or 'N/A'}\n"

        field_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": field_text.strip()
            }
        })

    return blocks + field_blocks


def format_pending_approvals(approvals, username):
    if not approvals:
        return [{
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":information_source: No pending approvals found for `{username}`"
            }
        }]

    blocks = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"Pending Approvals: {username}"
        }
    }]

    for approval in approvals[:5]:  # Limit to 5 most recent
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*• {approval.get('requestType', 'N/A')}*\n"
                    f"Requested by: `{approval.get('requestedBy', 'N/A')}`\n"
                    f"Status: `{approval.get('status', 'N/A')}`\n"
                    f"Date: `{approval.get('requestedDate', 'N/A')}`"
                )
            }
        })
        blocks.append({"type": "divider"})

    return blocks


def format_sav_roles(roles):
    if not roles:
        return [{
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": ":information_source: No roles found"
            }
        }]

    # Handle dictionary format
    if isinstance(roles, dict) and "savRoles" in roles:
        roles = roles["savRoles"]

    # Handle single role response
    if isinstance(roles, str):
        roles = [roles]

    blocks = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"Available Roles ({len(roles)})"
        }
    }]

    # Display roles in a scrollable section
    role_list = "\n".join([f"• {role}" for role in roles])
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": role_list
        }
    })

    return blocks

# ============================ MODAL HANDLERS ============================


def handle_user_lookup_submission(payload):
    try:
        user_id = payload['user']['id']
        channel_id = json.loads(payload['view']['private_metadata'])[
            'channel_id']
        values = payload['view']['state']['values']
        username = values['username_block']['username_input']['value'].strip()

        # Properly retrieve token from session dictionary
        session = user_sessions.get(user_id)
        token = session["token"] if session else None

        if not token:
            return jsonify({
                "response_action": "errors",
                "errors": {"username_block": "Session expired. Please login again using /savi-login"}
            })

        # Close the modal
        client.views_update(
            view_id=payload['view']['id'],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [{
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":hourglass_flowing_sand: Looking up user `{username}`..."}
                }]
            }
        )

        # Process in background
        threading.Thread(target=process_user_lookup, args=(
            username, token, channel_id, user_id)).start()
        return Response(), 200

    except Exception as e:
        logger.error(f"User lookup submission error: {str(e)}")
        return jsonify({
            "response_action": "errors",
            "errors": {"username_block": f"System error: {str(e)}"}
        })


def handle_pending_approvals_submission(payload):
    try:
        user_id = payload['user']['id']
        channel_id = json.loads(payload['view']['private_metadata'])[
            'channel_id']
        values = payload['view']['state']['values']
        username = values['username_block']['username_input']['value'].strip()

        # Properly retrieve token from session dictionary
        session = user_sessions.get(user_id)
        token = session["token"] if session else None

        if not token:
            return jsonify({
                "response_action": "errors",
                "errors": {"username_block": "Session expired. Please login again using /savi-login"}
            })

        # Close the modal
        client.views_update(
            view_id=payload['view']['id'],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [{
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":hourglass_flowing_sand: Checking approvals for `{username}`..."}
                }]
            }
        )

        # Process in background
        threading.Thread(target=process_pending_approvals,
                         args=(username, token, channel_id)).start()
        return Response(), 200

    except Exception as e:
        logger.error(f"Approvals submission error: {str(e)}")
        return jsonify({
            "response_action": "errors",
            "errors": {"username_block": f"System error: {str(e)}"}
        })


def handle_view_submissions(payload):
    callback_id = payload['view']['callback_id']

    if callback_id == "login_modal":
        return handle_login_submission(payload)
    elif callback_id in ["user_lookup_modal", "pending_approvals_modal"]:
        # Handle other view submissions here if needed
        return Response(), 200
    else:
        logger.warning(f"Unhandled view submission: {callback_id}")
        return Response(), 200


def handle_login_submission(payload):
    try:
        user_id = payload['user']['id']
        channel_id = json.loads(payload['view']['private_metadata'])[
            'channel_id']
        values = payload['view']['state']['values']
        username = values['username_block']['username_input']['value'].strip()
        password = values['password_block']['password_input']['value'].strip()

        token, expires_in, error = saviynt_login(username, password)
        if error or not token:
            return jsonify({
                "response_action": "errors",
                "errors": {"password_block": f"Login failed: {error}"}
            })

        # Save session with username
        user_sessions[user_id] = {
            "token": token,
            "expires_at": time.time() + expires_in,
            "saviynt_username": username  # Store Saviynt username
        }

        # Update the modal to show success
        client.views_update(
            view_id=payload['view']['id'],
            view={
                "type": "modal",
                "title": {"type": "plain_text", "text": "Login Successful"},
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f":white_check_mark: *Login successful as `{username}`!*"
                        }
                    }
                ]
            }
        )

        show_main_menu(channel_id, username)
        return Response(), 200

    except Exception as e:
        logger.error(f"Login submission error: {str(e)}")
        return jsonify({
            "response_action": "errors",
            "errors": {"password_block": f"System error: {str(e)}"}
        })

# ============================ SESSION MANAGEMENT ============================


def get_valid_user_token(user_id):
    """Get valid token for user or return None if expired"""
    if user_id in user_sessions:
        session_data = user_sessions[user_id]
        if time.time() < session_data["expires_at"] - 60:  # 60s buffer
            return session_data["token"]
        else:
            # Optionally add token refresh logic here
            del user_sessions[user_id]
    return None


# ============================ BLOCK ACTIONS ============================


def handle_block_actions(payload):
    try:
        user_id = payload['user']['id']
        trigger_id = payload['trigger_id']
        action_id = payload['actions'][0]['action_id']
        channel_id = payload.get('container', {}).get('channel_id')

        if not channel_id:
            return make_response("Missing channel_id", 400)

        # Handle logout
        if action_id == "logout_action":
            return handle_logout(user_id, channel_id)

        # For other actions, check session
        token = get_valid_user_token(user_id)
        if not token:
            client.chat_postMessage(
                channel=channel_id,
                text=":exclamation: Please login first using `/savi-login`."
            )
            return make_response("", 200)

        if action_id == "user_lookup_action":
            open_username_modal("user_lookup_modal",
                                "User Lookup", channel_id, trigger_id)
            return make_response("", 200)
        elif action_id == "pending_approvals_action":
            open_username_modal("pending_approvals_modal",
                                "Pending Approvals", channel_id, trigger_id)
            return make_response("", 200)
        elif action_id == "sav_roles_action":
            threading.Thread(target=process_sav_roles,
                             args=(token, channel_id)).start()
            return make_response("", 200)

        return make_response("", 200)

    except Exception as e:
        logger.exception(f"Block actions error: {e}")
        return make_response("Internal server error", 500)

# ============================ LOGOUT HANDLER ============================


def handle_logout(user_id, channel_id):
    try:
        if user_id in user_sessions:
            del user_sessions[user_id]
            message = ":wave: You've been successfully logged out."
        else:
            message = ":information_source: You weren't logged in."

        client.chat_postMessage(
            channel=channel_id,
            text=message,
            blocks=[{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            }]
        )
        return make_response("", 200)
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return make_response("Internal server error", 500)

# ============================ VIEW SUBMISSION HANDLER ============================


def handle_view_submission(payload):
    try:
        logger.info("Handling view submission")

        metadata_str = payload['view'].get('private_metadata', '')
        if not metadata_str:
            return make_response("Missing metadata", 400)

        metadata = json.loads(metadata_str)

        # Get session token before proceeding
        token = get_valid_token()
        if not token:
            return make_response("Session expired. Please login again using /savi-login.", 200)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        # Example usage — modify based on what you actually do next
        user_action_data = payload.get("view", {}).get(
            "state", {}).get("values", {})
        logger.info(f"User submitted data: {user_action_data}")

        # If you make a request to Saviynt here:
        # response = requests.post(SOME_SAVIYNT_API, json=..., headers=headers)

        return make_response("Submission processed successfully!", 200)

    except KeyError as ke:
        logger.error(f"Key error in handle_view_submission: {ke}")
        return make_response("Missing expected data in the submission.", 400)
    except Exception as e:
        logger.exception(f"Exception in handle_view_submission: {e}")
        return make_response("An unexpected error occurred.", 500)

# ============================ MODALS ============================


def open_username_modal(callback_id, title, channel_id, trigger_id):
    client.views_open(
        trigger_id=trigger_id,
        view={
            "type": "modal",
            "callback_id": callback_id,
            "private_metadata": json.dumps({"channel_id": channel_id}),
            "title": {"type": "plain_text", "text": title},
            "submit": {"type": "plain_text", "text": "Submit"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": "username_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "username_input"
                    },
                    "label": {"type": "plain_text", "text": "Username"}
                }
            ]
        }
    )
    return None

# ============================ ACTIONS ============================


def show_main_menu(channel_id, saviynt_username):
    client.chat_postMessage(
        channel=channel_id,
        text="Choose an option:",
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Welcome *{saviynt_username}*! Choose an action:"
                }
            },
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "🔍 User Lookup"},
                 "action_id": "user_lookup_action"},
                {"type": "button", "text": {"type": "plain_text", "text": "⏳ Pending Approvals"},
                 "action_id": "pending_approvals_action"},
                {"type": "button", "text": {"type": "plain_text", "text": "🔐 Saviynt Roles"},
                 "action_id": "sav_roles_action"},
                {"type": "button", "text": {"type": "plain_text", "text": "🚪 Logout"},
                 "action_id": "logout_action", "style": "danger"}
            ]}
        ]
    )

# ============================ PROCESSING FUNCTIONS ============================


def process_user_lookup(username, token, channel_id, user_id):
    try:
        # PAYLOAD STRUCTURE
        payload = {
            "filtercriteria": {"username": username},
            "showsecurityanswers": "1"
        }

        result = call_saviynt_api(GET_USER_URL, token, payload)

        # Handle API errors
        if "errorCode" in result and result["errorCode"] != "0":
            error_msg = result.get("msg", "Unknown API error")
            client.chat_postMessage(
                channel=channel_id,
                text=f":x: API Error: {error_msg}"
            )
            return

        # Check if user exists
        if not result.get("userlist"):
            client.chat_postMessage(
                channel=channel_id,
                text=f":warning: User `{username}` not found"
            )
            return

        user = result["userlist"][0]
        blocks = format_user_info(user)

        client.chat_postMessage(
            channel=channel_id,
            text=f"User info for {username}",
            blocks=blocks
        )

    except Exception as e:
        logger.error(f"User lookup error: {str(e)}")
        client.chat_postMessage(
            channel=channel_id,
            text=f":x: Error looking up user `{username}`: {str(e)}"
        )


def process_pending_approvals(username, token, channel_id):
    try:
        payload = {"username": username, "requestkey": "3484"}
        result = call_saviynt_api(PENDING_APPROVALS_URL, token, payload)

        # ADD ERROR HANDLING
        if "errorCode" in result:
            if result["errorCode"] != "0":
                error_msg = result.get("msg", "Unknown API error")
                raise Exception(f"API Error: {error_msg}")
        # END OF ADDED SECTION

        approvals = result.get("results", [])
        blocks = format_pending_approvals(approvals, username)

        client.chat_postMessage(
            channel=channel_id,
            text=f"Pending approvals for {username}",
            blocks=blocks
        )
    except Exception as e:
        logger.error(f"Approvals error: {str(e)}")
        client.chat_postMessage(
            channel=channel_id,
            text=f":x: Error checking approvals for `{username}`: {str(e)}"
        )


def process_sav_roles(token, channel_id):
    try:
        # Use GET request instead of POST
        result = call_saviynt_api(
            GET_SAVROLES_URL,
            token,
            method='GET'
        )

        # Handle API errors
        if "errorCode" in result:
            if result["errorCode"] != "0":
                error_msg = result.get("msg", "API error")
                client.chat_postMessage(
                    channel=channel_id,
                    text=f":x: API Error: {error_msg}"
                )
                return

        # Handle response format
        roles = []
        if isinstance(result, list):
            roles = result
        elif "savRoles" in result:
            roles = result["savRoles"]

        blocks = format_sav_roles(roles)
        client.chat_postMessage(
            channel=channel_id,
            text="Available Saviynt roles",
            blocks=blocks
        )

    except Exception as e:
        logger.error(f"Roles error: {str(e)}")
        client.chat_postMessage(
            channel=channel_id,
            text=f":x: Error fetching roles: {str(e)}"
        )


def format_sav_roles(roles):
    if not roles:
        return [{
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": ":information_source: No roles found"
            }
        }]

    # If we have a dictionary, extract role names
    if isinstance(roles, dict):
        roles = list(roles.values())

    blocks = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"Available Roles ({len(roles)})"
        }
    }]

    # Group roles into chunks of 10
    for i in range(0, len(roles), 10):
        chunk = roles[i:i+10]
        role_list = "\n".join([f"• {role}" for role in chunk])

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": role_list
            }
        })

    return blocks

# ============================ APP START ============================


if __name__ == "__main__":
    if not SLACK_BOT_TOKEN or not os.environ.get("SLACK_SIGNING_SECRET"):
        logger.error("Missing required Slack env variables")
        exit(1)

    app.run(host="0.0.0.0", port=3000)
