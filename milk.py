from flask import Blueprint, request, Response, redirect
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('milk', __name__, url_prefix='/milk')

# HTTP status code: message
msg = {
    "200": "OK",
    "201": "Created",
    "204": "No Content",
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable"
}


# Create a Milk Option
# View all Milk options
@bp.route('', methods=['POST', 'GET'])
def milk_get_post():
    # get the list of all the milk options
    query = client.query(kind=constants.milk)
    results = list(query.fetch())

    # add a milk option
    if request.method == 'POST':
        content = request.get_json()
        # if missing any of the 3 attributes, return 400
        attributes = content.keys()
        if 'name' not in attributes or 'description' not in attributes or \
                'vegan' not in attributes:
            return Response(json.dumps(msg["400"]), status=400,
                            mimetype='application/json')

        # Ensure the name of a milk option is unique across all milk options
        # duplicate name -> 403 error
        for e in results:
            if e["name"] == content["name"]:
                return Response(json.dumps(msg["403"]), status=403,
                                mimetype='application/json')

        # return 201 if successful
        new_milk = datastore.entity.Entity(key=client.key(constants.milk))

        new_milk.update({"name": content["name"], "description": content[
            "description"], "vegan": content["vegan"]})
        client.put(new_milk)
        # add the id
        new_milk["id"] = new_milk.key.id
        # add the self link
        new_milk.update({"self": request.base_url + '/' + str(new_milk["id"])})
        client.put(new_milk)

        return Response(json.dumps(new_milk), status=201,
                        mimetype='application/json')

    # view all the milk options
    if request.method == 'GET':
        return Response(json.dumps(results), status=200,
                        mimetype='application/json')


# View a milk option: GET
# Update a milk option: PATCH
# Update a milk option: PUT
# Delete a milk option: DELETE
@bp.route('<milk_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def milk_get_patch_put_delete(milk_id):
    # Get a milk
    milk_key = client.key(constants.milk, int(milk_id))
    milk = client.get(key=milk_key)
    # if the milk option does not exist, return 404
    if milk is None:
        return Response(json.dumps((msg["404"])), status=404,
                        mimetype='application/json')

    # if the milk option exists, perform GET
    if request.method == 'GET':
        # check Accept -> 406 error
        if 'application/json' != request.headers['Accept']:
            return Response(json.dumps(msg["406"]), status=406,
                            mimetype='application/json')

        # if the key exists, return the milk with 200
        milk["id"] = milk_id
        return Response(json.dumps(milk), status=200,
                        mimetype='application/json')

    # Edit a milk option: 1) PATCH 2) PUT
    elif request.method == 'PATCH' or request.method == 'PUT':
        content = request.get_json()
        attributes = content.keys
        # Ensure the name of a milk is unique across all milk options
        # duplicate name -> 403 error
        query = client.query(kind=constants.milk)
        results = list(query.fetch())
        if 'name' in content:
            for e in results:
                if e["name"] == content["name"]:
                    return Response(json.dumps(msg["403"]), status=403,
                                    mimetype='application/json')

        # 1. Edit a milk with PATCH: any subset of attributes
        if request.method == 'PATCH':
            if 'name' not in attributes and 'description' not in attributes \
                    and 'vegan' not in attributes:
                return Response(json.dumps(msg["400"]), status=400,
                                mimetype='application/json')

        # 2. Edit a milk with PUT: must modify all attributes
        if request.method == 'PUT':
            if 'name' not in attributes or 'description' not in attributes \
                    or 'vegan' not in attributes:
                return Response(json.dumps(msg["400"]), status=400,
                                mimetype='application/json')

        # return 200 if successful
        for attribute in attributes:
            milk.update({attribute: content[attribute]})
        milk["id"] = milk.key.id
        client.put(milk)
        return Response(json.dumps(milk), status=200,
                        mimetype='application/json')

    # Delete a boat
    elif request.method == 'DELETE':
        # if the key exists, delete the milk option -> 204
        client.delete(milk_key)
        return Response(status=204, mimetype='application/json')

