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
	return {'status': 'success', 'message': str(encoded.decode('utf-8'))}


#Validaing the user and generating the token on success
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

#Validating user with preloaded creds
def validate_user(user_details= None):
    if user_details:
        if user_creds['username'] == user_details['username'] and user_creds['password'] == user_details['password']:
            return True
    return False

@app.route('/validateToken', methods=['POST'], cors=True)
def validate_token():
    try:
        token = app.current_request.json_body['token']
    except Exception:
        return {'status': 'failed', 'message': 'Please provide the token'}
    try:
        _ = jwt.decode(token, secret, leeway=10, algorithms=['HS256'])
        return {'status':'success', 'message': 'Valid token'}
    except jwt.ExpiredSignatureError:
        return {'status': 'failed', 'message': 'Token expired'}
	