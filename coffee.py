from flask import Blueprint, request, Response, redirect
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('coffee', __name__, url_prefix='/coffee')