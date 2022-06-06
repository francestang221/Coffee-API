import constants
import milk

from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, Response
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

# reference: Module 7 - Exploration - Authentication in Python
# url: https://canvas.oregonstate.edu/courses/1870359/pages/exploration-authentication-in-python?module_item_id=22099672

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
app.register_blueprint(milk.bp)

client = datastore.Client()

CLIENT_ID = '04VKhZ8i6uw4ermKXR34hGBmBsX6Z62Q'
CLIENT_SECRET = 'vRwJyQu_bDFcGa7P4hWT37YeMzE9QOJreyqqzpxZisdWFurqKFZVMl0k1hpIFsqu'
DOMAIN = 'tangmm-project.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# HTTP status code: message
msg = {
    "200": "OK",
    "201": "Created",
    "204": "No Content",
    "400": "Bad Request",
    "400_missing": "Bad Request: At least one required attribute is missing",
    "401": "Unauthorized",
    "403_wrong_owner": "Forbidden: You are not the owner of the recipe",
    "403_duplicate": "Forbidden: The recipe name has been taken",
    "404_get_coffee": "Not Found: No coffee with this coffee_id exists",
    "404_coffee_milk": "Not Found: No coffee with this coffee_id exists "
                       "and/or no milk with this milk_id exists",
    "405": "Method Not Allowed",
    "406": "Not Acceptable: Unsupported MIME type"
}

# store all users after they login
users = {"all users": []}


############################################################################

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


# check if the jwt is valid or not
def is_valid_jwt(request):
    # if verify_jwt did not raise error, return True
    # else return False
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False
        return True
    else:
        return False


############################################################################

@app.route('/')
def index():
    return "Please navigate to /coffee to use this API"


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    """add to the users list"""
    if len(users["all users"]) < 2:
        sub = payload["sub"]
        email = payload["email"]
        users["all users"].append({"sub": sub, "email": email})
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


############################################################################

# coffee CRUD [Protected]
@app.route('/coffee', methods=['GET', 'POST'])
def coffee_get_post():
    payload = verify_jwt(request)

    query = client.query(kind=constants.coffee)
    query.add_filter("owner", "=", payload["sub"])
    results = list(query.fetch())

    # create a coffee recipe if the Authorization header contains a valid jwt
    if request.method == 'POST':
        content = request.get_json()
        new_coffee = datastore.entity.Entity(key=client.key(constants.coffee))
        # if missing any of the 3 attributes, return 400
        attributes = content.keys()
        if 'name' not in attributes or 'description' not in attributes or \
                'ingredients' not in attributes:
            return Response(json.dumps(msg["400_missing"]), status=400,
                            mimetype='application/json')

        # Ensure the name of a coffee recipe is unique within one owner's
        # recipes
        # duplicate name -> 403 error
        for e in results:
            if e["name"] == content["name"]:
                return Response(json.dumps(msg["403_duplicate"]), status=403,
                                mimetype='application/json')

        new_coffee.update({"name": content["name"],
                           "description": content["description"],
                           "ingredients": content["ingredients"]})
        client.put(new_coffee)
        # set the id of the boat
        new_coffee["id"] = new_coffee.key.id
        # set the owner of the boat to the sub of the decoded jwt
        new_coffee["owner"] = payload["sub"]
        # set the self link
        new_coffee.update({"self": request.base_url + '/' + str(new_coffee[
                                                                    "id"])})
        new_coffee.update({"milk options": {}})
        client.put(new_coffee)
        # return 201
        return Response(json.dumps(new_coffee), status=201,
                        mimetype='application/json')

    if request.method == 'GET':
        # only show coffee recipes owned by the current JWT
        query = client.query(kind=constants.coffee)
        # only show what is owned by the owner with the current JWT
        query.add_filter("owner", "=", payload["sub"])
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + \
                       "&offset=" + str(next_offset)
        else:
            next_url = None

        output = {"coffee recipes": results}
        if next_url:
            output["next"] = next_url

        output["count"] = len(results)
        return Response(json.dumps(output), status=200,
                        mimetype='application/json')


# delete, edit, view a coffee
@app.route('/coffee/<coffee_id>', methods=['DELETE', 'PATCH', 'PUT', 'GET'])
def get_put_patch_delete_coffee(coffee_id):
    payload = verify_jwt(request)
    coffee_key = client.key(constants.coffee, int(coffee_id))
    coffee = client.get(key=coffee_key)

    # Verify the coffee exists
    if coffee is None:
        return Response(json.dumps(msg["404_get_coffee"]), status=404,
                        mimetype='application/json')

    # Verify if the coffee is owned by the current JWT
    if coffee["owner"] != payload["sub"]:
        return Response(json.dumps(msg["403_wrong_owner"]), status=403,
                        mimetype='application/json')

    # View a coffee recipe
    if request.method == 'GET':
        return Response(json.dumps(coffee), status=200,
                        mimetype='application/json')

    # Delete a coffee
    if request.method == 'DELETE':
        # delete the recipe from all of the milk options
        for m in coffee["milk options"]:
            milk_key = client.key(constants.milk, int(m))
            milk = client.get(key=milk_key)
            for c in milk["recipes"]:
                if c == coffee_id:
                    del milk["recipes"][c]
                    break
            client.put(milk)
        client.delete(coffee_key)
        return Response(status=204)

    # Edit a coffee recipe with 1) PATCH 2) PUT
    # Edit a coffee option: 1) PATCH 2) PUT
    if request.method == 'PATCH' or request.method == 'PUT':
        content = request.get_json()
        attributes = content.keys()
        # Ensure the name of a coffee recipe is unique
        # duplicate name -> 403 error
        query = client.query(kind=constants.coffee)
        results = list(query.fetch())

        if 'name' in content:
            for e in results:
                if e["name"] == content["name"]:
                    return Response(json.dumps(msg["403_duplicate"]),
                                    status=403,
                                    mimetype='application/json')

        # 1. Edit a coffee with PATCH: any subset of attributes
        if request.method == 'PATCH':
            if 'name' not in attributes and 'description' not in attributes \
                    and 'ingredients' not in attributes:
                return Response(json.dumps(msg["400_missing"]), status=400,
                                mimetype='application/json')

        # 2. Edit a coffee with PUT: must modify all attributes
        if request.method == 'PUT':
            if 'name' not in attributes or 'description' not in attributes \
                    or 'ingredients' not in attributes:
                return Response(json.dumps(msg["400_missing"]), status=400,
                                mimetype='application/json')

        # return 200 if successful
        for attribute in attributes:
            coffee.update({attribute: content[attribute]})
        client.put(coffee)
        return Response(json.dumps(coffee), status=200,
                        mimetype='application/json')


@app.route('/coffee/<coffee_id>/milk/<milk_id>', methods=['PUT', 'DELETE'])
def coffee_put_delete_milk(coffee_id, milk_id):
    payload = verify_jwt(request)
    coffee_key = client.key(constants.coffee, int(coffee_id))
    coffee = client.get(key=coffee_key)
    milk_key = client.key(constants.milk, int(milk_id))
    milk = client.get(key=milk_key)

    # check if milk and coffee both exist
    if coffee is None or milk is None:
        return Response(json.dumps(msg["404_coffee_milk"]), status=404,
                        mimetype='application/json')

    # Verify if the coffee is owned by the current JWT
    if coffee["owner"] != payload["sub"]:
        return Response(json.dumps(msg["403_wrong_owner"]), status=403,
                        mimetype='application/json')

    if request.method == 'PUT':
        # check if the milk option already exists
        if milk_id in coffee["milk options"]:
            return Response(msg["403_duplicate"], status=403,
                            mimetype='application/json')

        # key-value: id -> name
        coffee["milk options"][milk_id] = milk["name"]
        client.put(coffee)
        milk["recipes"][coffee_id] = coffee["name"]
        client.put(milk)

        return Response(json.dumps(coffee), status=200,
                        mimetype='application/json')

    # Delete a milk option from a coffee recipe
    if request.method == 'DELETE':
        for m in coffee["milk options"]:
            if m == milk_id:
                del coffee["milk options"][m]
                break
        client.put(coffee)

        # update the recipes for the milk option
        for c in milk["recipes"]:
            if c == coffee_id:
                del milk["recipes"][c]
                break
        client.put(milk)

        return Response(json.dumps(coffee), status=200,
                        mimetype='application/json')


# get all users
@app.route('/users', methods=['GET'])
def get_users():
    # check Accept -> 406 error
    if 'application/json' != request.headers['Accept']:
        return Response(json.dumps(msg["406"]), status=406,
                        mimetype='application/json')
    return Response(json.dumps(users), status=200, mimetype='application/json')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
