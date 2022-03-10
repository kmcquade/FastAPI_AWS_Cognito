import secrets
import time

import aiohttp
import requests
from fastapi import APIRouter, Cookie, FastAPI, Request, status
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

import jwt
from jose import jwk, jwt
from jose.utils import base64url_decode

from AWSLoginHandler.common import generate_query_params, generate_state
from AWSLoginHandler.flows.base import OAuthManager
from AWSLoginHandler.flows.pkce.verifier_challenge import generate_pkce_pair

__all__ = ["PKCEManager"]


class PKCEAuthorizationRequest(BaseModel):
    response_type: str = "code"
    client_id: str
    redirect_uri: str
    state: str
    scope: str
    code_challenge: str
    code_challenge_method: str = "S256"


class PKCETokenRequest(BaseModel):
    grant_type: str = "authorization_code"
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str


class CodeResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class PKCEManager(OAuthManager):
    def __init__(
        self, user_pool_domain: str, client_id: str, userpool_id: str, login_prefix: str = "/login",
    ):
        self.state = None
        self.code_verifier = None
        self.code_challenge = None
        self.redirect_uri = None
        self.user_pool_domain = user_pool_domain
        self.authorization_url = f"{user_pool_domain}/oauth2/authorize"
        self.token_url = f"{user_pool_domain}/oauth2/token"
        self.refresh_url = f"{user_pool_domain}/oauth2/token"
        self.user_info_url = f"{user_pool_domain}/oauth2/userInfo"
        self.client_id = client_id
        self.login_prefix = login_prefix
        self.user_pool_id = userpool_id
        self.region = self.user_pool_id.split("_")[0]
        self.keys_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"

        self.keys = requests.get(self.keys_url).json()["keys"]

    def set_state(self):
        self.state = generate_state()

    def set_code_verifier_and_challenge(self):
        self.code_verifier, self.code_challenge = generate_pkce_pair()

    def attach_to_app(self, app: FastAPI):
        router = APIRouter(prefix=self.login_prefix)

        @router.get("/")
        async def login_redirect(request: Request):
            self.set_state()
            self.set_code_verifier_and_challenge()
            self.redirect_uri = f"{request.base_url}{self.login_prefix.lstrip('/')}/redirect"
            pkce_authorization_request = PKCEAuthorizationRequest(
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                scope="email+openid+phone",
                state=self.state,
                code_challenge=self.code_challenge,
                code_challenge_method="S256",
            )

            query_params = generate_query_params(**pkce_authorization_request.dict())
            authorization_redirect_uri = f"{self.authorization_url}?{query_params}"

            response = RedirectResponse(authorization_redirect_uri, status_code=status.HTTP_307_TEMPORARY_REDIRECT,)

            response.set_cookie(
                key="post_redirect_uri", value=request.headers.get("referer"), httponly=True,
            )
            response.set_cookie(key="state", value=self.state, httponly=True)
            return response

        @router.get("/redirect")
        async def redirect(request: Request, post_redirect_uri: str = Cookie(None)):
            returned_state = request.query_params["state"]
            if not secrets.compare_digest(self.state, returned_state):
                raise HTTPException(detail="Invalid request", status_code=status.HTTP_401_UNAUTHORIZED)

            token_data = PKCETokenRequest(
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code=request.query_params["code"],
                code_verifier=self.code_verifier,
            )

            form_data = aiohttp.FormData(fields=token_data.dict())
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            async with aiohttp.ClientSession() as session:
                async with session.post(self.token_url, data=form_data, headers=headers) as server_response:
                    token_response = await server_response.json()

            if server_response.status == status.HTTP_200_OK:
                token_response = CodeResponse(**token_response)
                response = RedirectResponse(post_redirect_uri)

                response.set_cookie(
                    key="access_token",
                    value=token_response.access_token,
                    expires=token_response.expires_in,
                    httponly=True,
                )
                response.set_cookie(
                    key="refresh_token", value=token_response.refresh_token, httponly=True,
                )
                response.delete_cookie("post_redirect_uri")
                response.delete_cookie("state")
                return response
            else:
                raise HTTPException(detail=token_response, status_code=server_response.status)

        @router.get("/token/refresh")
        async def refresh_access_token(request: Request):
            """
            The refresh endpoint should go to the cognito endpoint and exchange the refresh_token cookie for a new
            access token. If the refresh token is invalid, or for some reason cannot get a new access token, it
            should redirect to the /logout endpoint.

            The 'get_user' and 'get_user_info' should redirect to here to try and refresh the access token if they
            are not able to get the user info for some reason (token invalid). They should use
            'request.get_url_for('/token/refresh')' to get the url to go to and use a tem

            The refresh token endpoint should use a query parameter to redirect back to the page, or use
            'request.headers.get("referer")' to get the page location from the 'get_user' and 'get_user_info'
            functions.
            """
            raise HTTPException(
                detail="Not currently implemented", status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )

        @router.get("/logout")
        async def logout(request: Request):
            """
            The logout endpoint should go to the aws cognito /logout endpoint as well as
            """
            raise HTTPException(
                detail="Not currently implemented", status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )

        app.include_router(router)

    async def get_user_info(self, request: Request):
        access_token = request.cookies.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as server_response:
                response = await server_response.json()
        if server_response.status == status.HTTP_200_OK:
            return response
        return None

    async def get_user(self, request: Request):
        user_info = await self.get_user_info(request)
        if user_info:
            return user_info
        return None

    async def get_users_token_payload(self, request: Request):
        access_token = request.cookies.get("access_token")
        payload = self.get_token_payload(access_token)
        return payload

    def get_token_payload(self, token):
        headers = jwt.get_unverified_headers(token)
        kid = headers["kid"]
        # search for the kid in the downloaded public keys
        key_index = -1
        for i in range(len(self.keys)):
            if kid == self.keys[i]["kid"]:
                key_index = i
                break
        if key_index == -1:  # Public key not found in jwks.json
            return None
        # construct the public key
        public_key = jwk.construct(self.keys[key_index])
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit(".", 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):  # Signature verification failed
            return None
        print("Signature successfully verified")
        # since we passed the verification, we can now safely
        # use the unverified claims
        claims = jwt.get_unverified_claims(token)
        # additionally we can verify the token expiration
        if time.time() > claims["exp"]:
            print("Token is expired")
            return False
        # and the Audience  (use claims['client_id'] if verifying an access token)
        if claims["client_id"] != self.client_id:  # Token was not issued for this audienc
            return None
        # now we can use the claims
        print(claims)
        return claims
