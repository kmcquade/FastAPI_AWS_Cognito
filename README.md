# AWS Login Handler

A helper module for attaching to a FastAPI app for user login using AWS Cognito.

## Installation
You can install with pip

    pip install --extra-index-url http://pypi.bar.local --trusted-host pypi.bar.local AWSLoginHandler


## Usage
To use add user login to a FastAPI app, simply create a manager and attach it to an app:

```commandline
from fastapi import FastAPI
from AWSLoginHandler.flows.pkce.manager import PKCEManager

api = FastAPI()

oauth_manager = PKCEManager(
    user_pool_domain="https://auth.bar-tech.uk",
    client_id="7ks1311iid23h0cnvg2o3i4g7k",
    userpool_id="eu-west-2_tMeCEUTj8",
)

oauth_manager.attach_to_app(api)
```

Then to allow a user to login, simply redirect the user to the `/login` endpoint. For example:

```commandline
<a href='{request.url_for('login_redirect')}'>Login</a>
```

You can get the user information using dependancy injection on your endpoint:

```commandline
@api.get("/")
async def homepage(request: Request, user_info=Depends(oauth_manager.get_user)):
    return user_info
```

In addition, you can verify the users JWT token and get it's info using `get_users_token_payload`:

```commandline
@api.get("/payload")
async def payload(request: Request, user_payload=Depends(oauth.get_user_token_payload)):
    return user_payload
```

See [the amazon docs](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html) for more
information on JWT token payloads.

For a demo, clone the repo to your device. Within the repository, there is a simple FastAPI app in the example folder. 

Create a conda environment, install the dependencies and then run the app

```commandline
conda create -n aws_login_handler
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Run the code and go to

```commandline
http://localhost:8021/
```

The aim of this package is to make it simple to add login handling using AWS Cognito. Before you are able to use the app,
you must first set up an AWS Cognito user pool. Go to [aws cognito](https://eu-west-2.console.aws.amazon.com/cognito/v2/idp/user-pools?region=eu-west-2)
and press 'create user pool'. Set up the pool for your use case.

When you reach `initial app client`, select the correct one for your use case. Public client is used for deployed
apps where you no longer control the source code, confidential client is for server side web apps. Currently, only 
public client is supported. When selecting public client, choose "dont generate a client secret".

For simplicity, select 'Use the Cognito Hosted UI'.

For allowed callback URLs, enter
```commandline
http://localhost:8021/login/redirect
```
Where PORT is the port that you will be running your local test app from (i.e., 8000). After this, keep everything as
default and create your Cognito user pool. It may take some time for the UI to be built.

While your app is being built, go into the example FastAPI app and fill out the details for the PKCEManager for your user pool.
The details can be found by:
* user_pool_id: Go to [here](https://eu-west-2.console.aws.amazon.com/cognito/v2/idp/user-pools?region=eu-west-2) and the pool id is next to the pool name
* client_id: Click on your user pool, go to app integration, go to app client list and the client id is next to the app name
* userpool_id: Scroll to the top of the window, the user pool id is under 'User pool overview'

You can now run `basic_fastapi_app.py` and navigate to `http://localhost:8021/`. Follow the instructions.

### Black and Isort

We use [black](https://github.com/psf/black) to handle code formatting, and [isort](https://pycqa.github.io/isort/) 
for header ordering. 

```commandline
conda create -n aws_login_handler
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install
```

### Todo

* Implement authorization code flow
* Implement '/logout' and 'token/refresh' endpoints
