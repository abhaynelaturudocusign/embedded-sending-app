from flask import Flask, render_template_string, request, redirect
import requests
import json
import base64
import time
from datetime import datetime, timedelta

# JWT specific imports
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

cached_access_token = None
token_expiration_time = None

def get_jwt_token():
    global cached_access_token, token_expiration_time

    if cached_access_token and token_expiration_time and datetime.utcnow() < token_expiration_time:
        return cached_access_token

    try:
        # --- NEW METHOD: Read key from a file ---
        with open("private.key", "r") as key_file:
            private_key = key_file.read()
        # --- END OF NEW METHOD ---

        current_time = int(time.time())
        jwt_payload = {
            "iss": "dfba8887-518b-488d-a787-76794a3a6c9d", # Make sure to replace this
            "sub": "f5e619d1-0227-42e9-96f5-17e82cd4fa4c",         # And this
            "aud": "account-d.docusign.com",
            "iat": current_time,
            "exp": current_time + 3600,
            "scope": "signature impersonation"
        }

        jwt_token = jwt.encode(jwt_payload, private_key, algorithm='RS256')
        url = "https://account-d.docusign.com/oauth/token"
        response = requests.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token
            }
        )
        response.raise_for_status()
        token_data = response.json()
        cached_access_token = token_data['access_token']
        token_expiration_time = datetime.utcnow() + timedelta(seconds=token_data['expires_in'] - 60)
        return cached_access_token

    except FileNotFoundError:
        print("FATAL ERROR: The private.key file was not found in the application directory.")
        raise
    except Exception as e:
        print(f"An error occurred during token generation: {e}")
        raise

def pdf_to_base64(pdf_path):
    with open(pdf_path, "rb") as pdf_file:
        pdf_bytes = pdf_file.read()
        base64_bytes = base64.b64encode(pdf_bytes)
        base64_string = base64_bytes.decode("utf-8")  # Convert to string
    return base64_string


def create_envelope(access_token):
    url = f"https://demo.docusign.net/restapi/v2.1/accounts/5d72dc01-0dc7-4f64-9380-593270983810/envelopes"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    envelope_definition = {
        "emailSubject": "Please sign this document",
        "status": "created",  # Draft envelope
        "documents": [{
            "documentBase64": pdf_to_base64("sample pdf.pdf"),
            "name": "Sample Document",
            "fileExtension": "pdf",
            "documentId": "1"
        }],
        "recipients": {
            "signers": [{
                "email": "abhay.kumar60@gmail.com",
                "name": "abhay kumar",
                "recipientId": "1",
                "clientUserId": "e2ebc202-bc69-49c3-ac10-c7177a853c94",
                "tabs": {
                    "signHereTabs": [{
                        "anchorString": "/quam/",
                        "anchorYOffset": "10",
                        "anchorUnits": "pixels"
                    }]
                }
            }]
        }
    }

    response = requests.post(url, headers=headers, data=json.dumps(envelope_definition))
    response.raise_for_status()
    print(response.json()['envelopeId'])
    return response.json()['envelopeId']


def generate_sender_view_url(access_token, envelope_id):
    url = f"https://demo.docusign.net/restapi/v2.1/accounts/5d72dc01-0dc7-4f64-9380-593270983810/envelopes/{envelope_id}/views/sender"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    sender_view_request = {
        "returnUrl": "https://www.docusign.com",  # Where to redirect after sending
    }

    response = requests.post(url, headers=headers, json=sender_view_request)
    response.raise_for_status()
    return response.json()['url']


@app.route("/")
def embedded_sender_url():
    try:
        token = get_jwt_token()
        envelope_id = create_envelope(token)
        sender_view_url = generate_sender_view_url(token, envelope_id)
        print(f"Sender View URL: {sender_view_url}")
        return redirect(sender_view_url)  # Redirects user to embedded sending view
    except Exception as e:
        return f"Error occurred: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True)
