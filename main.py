import os
import urllib

from flask import Flask, flash, request, redirect, url_for, jsonify, make_response, send_from_directory, render_template

from emoji import emojize
from umbral import pre, keys, config, signing, params
from umbral.config import default_params
from umbral.cfrags import CapsuleFrag
from umbral.kfrags import KFrag
from umbral.keys import UmbralPublicKey
from flask_cors import CORS, cross_origin
import base64
import zlib

app = Flask(__name__) 
CORS(app)
# firebase_admin.initialize_app(options={
#     'databaseURL': 'https://<DB_NAME>.firebaseio.com'
# })

# Port variable to run the server on.
PORT = os.environ.get('PORT')

# @app.errorhandler(404)
# @cross_origin()
# def not_found(error):
#     """ error handler """
#     LOG.error(error)
#     return make_response(jsonify({'error': 'Not found'}), 404)
# app name 
@app.errorhandler(404)
def not_found(error):
    """ error handler """
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.route('/')
def index():
    """ static files serve """
    return send_from_directory('dist', 'index.html')


# @app.route('/')
# @cross_origin()
# def hello():
#     name = request.args.get('name', 'World')
#     return emojize(f'Hello {name}!')

@app.route('/doctors-board')
@cross_origin()
def get_board():
    
    data = [
                {
                    'created_at':'2019-04-07T17:43:25Z',
                    'number':'12',
                    'state':'ready',            
                    'title': 'doctor1' 
                },
                {            
                    'created_at':'2019-04-05T17:43:25Z',
                    'number':'13',
                    'state':'ready',            
                    'title': 'doctor2'
                },
                {            
                    'created_at':'2019-04-03T17:43:25Z',
                    'number':'15',
                    'state':'ready',            
                    'title': 'doctor3'
                }
    ]
    count = 15719
    dictToReturn = {
        'items':data,
        'total_count':count
    }
    return jsonify(dictToReturn)

@app.route("/generate_key_pair", methods=['POST'])
@cross_origin()
def generate_secret_key():
    alices_private_key = keys.UmbralPrivateKey.gen_key()
    alices_public_key = alices_private_key.get_pubkey()

    alices_signing_key = keys.UmbralPrivateKey.gen_key()
    alices_verifying_key = alices_signing_key.get_pubkey()
    alices_signer = signing.Signer(private_key=alices_signing_key)

    # Generate Umbral keys for Bob.
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = bobs_private_key.get_pubkey()
    plaintext = b'Proxy Re-Encryption is cool!'
    ciphertext, capsule = pre.encrypt(alices_public_key, plaintext)

    # Decrypt data with Alice's private key.
    cleartext = pre.decrypt(ciphertext=ciphertext,
                            capsule=capsule,
                            decrypting_key=alices_private_key)
    kfrags = pre.generate_kfrags(delegating_privkey=alices_private_key,
                             signer=alices_signer,
                             receiving_pubkey=bobs_public_key,
                             threshold=10,
                             N=20)
    return jsonify(
        {
            "encrypted_result": f'{kfrags}'
        } 
    )

@app.route("/token-re-key", methods=['POST'])
@cross_origin()
def generate_token():
    input_json = request.get_json(force=True) 
    print ('data from client:', input_json)
    dictToReturn = {'token': 42}
    return jsonify(dictToReturn) 

@app.route("/re-capsule", methods=['POST'])
@cross_origin()
def re_capsule():
    input_json = request.get_json(force=True) 
    print ('data from client:', input_json)
    #config.set_default_curve()
    curve = config.default_curve()
    params = default_params()
    #params = params.UmbralParameters(curve=curve)
    delegating_from_hex = UmbralPublicKey.from_bytes(bytes.fromhex(input_json.delegating))
    receiving_from_hex = UmbralPublicKey.from_bytes(bytes.fromhex(input_json.receiving))
    verifying_from_hex = UmbralPublicKey.from_bytes(bytes.fromhex(input_json.verifying))
    #capsule_from_hex = pre.Capsule.from_bytes(params, bytes.fromhex(input_json.capsule))
    #capsule_from_hex.set_correctness_keys(delegating=delegating_from_hex,
    #                             receiving=receiving_from_hex,
    #                             verifying=verifying_from_hex)
    #rCapsule = capsule_from_hex.to_bytes().hex()
    #print(rCapsule)
    reCapsule = {
         'capsule':input_json.capsule
     }
    return jsonify(input_json)

@app.route("/doc-capsule/<int:capsule_id>", methods=['GET'])
@cross_origin()
def doc_capsule(capsule_id):
    
    # with shelve.open(FILENAME) as states:
    #     states["delegating"] = "delegating"
    #     states["receiving"] = "receiving"
    #     states["verifying"] = "verifying"
    # 
    # with shelve.open(FILENAME) as states:
    # dictToReturn = {
    #         'delegating':states["delegating"],
    #         'receiving':states["receiving"],
    #         'verifying':states["verifying"] 
    # }
    dictToReturn = {
            'delegating':'delegating',
            'receiving':'receiving',
            'verifying':'verifying' 
    }
    return jsonify(dictToReturn)