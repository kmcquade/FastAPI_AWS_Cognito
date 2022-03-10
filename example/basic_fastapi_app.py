from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse

import uvicorn

from AWSLoginHandler.flows.pkce.manager import PKCEManager

api = FastAPI()

oauth_manager = PKCEManager(
    user_pool_domain="https://auth.bar-tech.uk",
    client_id="7ks1311iid23h0cnvg2o3i4g7k",
    userpool_id="eu-west-2_tMeCEUTj8",
)

oauth_manager.attach_to_app(api)


@api.get("/")
async def homepage(request: Request, user=Depends(oauth_manager.get_user)):
    if user:
        payload = await oauth_manager.get_users_token_payload(request)
        return user, payload
    else:
        return HTMLResponse(f"Not logged in... click <a href='{request.url_for('login_redirect')}'>here</a> to login")


uvicorn.run(api, port=8021)
