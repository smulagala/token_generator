from chalice import Chalice
from chalice import BadRequestError
import datetime
import jwt
import json

#Change this secret in prod
secret = 'secret'
#Mocking user details 
user_creds = {"username": "mulagala", "password": "password"}
app = Chalice(app_name='token_generator')


class MissingUserDetails(Exception):
	pass

@app.route('/', methods=['POST'])
def index():
    return {'hello': 'world'}


#Generate the token
@app.route('/generatetoken', methods=['POST'])
def generate_token():
	encoded= jwt.encode({'data': 'some_data',
     'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300)
                        },secret, algorithm='HS256')
    # encoded = encoded.encode()
	return {'status': 'success', 'message': json.dumps(encoded.decode('utf-8'))}


@app.route('/users', methods=['POST'], cors=True)
def validate_user_and_generate_token():
    try:
        user_as_json = app.current_request.json_body 
    except BadRequestError:
        return {'status': 'failed', 'message': 'Provide user credentials'}
    print(user_as_json)
    if validate_user(user_as_json):
        return generate_token()
    return {'status': 'failed', 'message': 'Invalid user credentials'}

def validate_user(user_details= None):
	if user_details:
		if user_creds['username'] == user_details['username'] and user_creds['password'] == user_details['password']:
			print('success')
			return True
	return False
	

# @app.route('/users', methods=['POST'], cors=True)
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.current_request.json_body
#     username = user_as_json['username']
#     password = user_as_json['password']
#     return {'user': username, 'password': password}
#     # We'll echo the json body back to the user in a 'user' key.
#     return {'user': user_as_json}

# The view function above will return {"hello": "world"}
# whenever you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
# @app.route('/hello/{name}')
# def hello_name(name):
#    # '/hello/james' -> {"hello": "james"}
#    return {'hello': name}
#
# @app.route('/users', methods=['POST'], cors=True)
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.current_request.json_body
#     # We'll echo the json body back to the user in a 'user' key.
#     return {'user': user_as_json}
#
# See the README documentation for more examples.
#