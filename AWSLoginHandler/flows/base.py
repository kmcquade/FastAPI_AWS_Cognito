import time
from typing import Any, Dict, List, Optional, Union

import aiohttp
from fastapi import Request, status
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param

import jwt
from jose import jwk, jwt
from jose.utils import base64url_decode


class OAuthManager:
    def __init__(
        self,
        flows: Union[OAuthFlowsModel, Dict[str, Dict[str, Any]]] = OAuthFlowsModel(),
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self.flows = flows
        self.scheme_name = scheme_name
        self.description = description

    async def get_user_info(self, access_token: str):
        headers = {"Authorization": f"Bearer {access_token}"}
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as server_response:
                response = await server_response.json()
        if server_response.status == status.HTTP_200_OK:
            return response
        return None

    async def get_users_token_payload(self, access_token: str):
        if access_token:
            return self.get_token_payload(access_token)
        return None

    async def get_user_info_and_payload(self, access_token: str):
        user_info = await self.get_user_info(access_token)
        token_payload = await self.get_users_token_payload(access_token)
        if user_info and token_payload:
            return {"user_info": user_info, "token_payload": token_payload}
        return None

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

    def get_user_info_from(self, token_location: List[str], auto_error: bool = True):
        return GetUserInfo(manager=self, token_location=token_location, auto_error=auto_error)


class GetUserInfo(OAuth2):
    def __init__(self, manager: OAuthManager, token_location=None, auto_error: bool = True):
        if token_location is None:
            token_location = ["header"]
        self.token_location = token_location
        self.manager = manager
        self.auto_error = auto_error
        super().__init__(
            flows=self.manager.flows,
            scheme_name=self.manager.scheme_name,
            description=self.manager.description,
            auto_error=self.auto_error,
        )

    async def __call__(self, request: Request):
        access_token = None
        if "header" in self.token_location:
            access_token = await self.get_authorization_code_from_header(request)
        if not access_token and ("cookie" in self.token_location):
            access_token = request.cookies.get("access_token")

        if access_token:
            user_data = await self.manager.get_user_info_and_payload(access_token)
            return user_data

        if self.auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return None

    async def get_authorization_code_from_header(self, request: Request):
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param
