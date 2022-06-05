from google.cloud import datastore
from flask import Flask, request
import json
import coffee
import milk

app = Flask(__name__)
app.register_blueprint(coffee.bp)


@app.route('/')
def index():
    return "Please navigate to /coffee to use this API"


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)