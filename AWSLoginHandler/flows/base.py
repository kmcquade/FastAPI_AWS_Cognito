import json
import random
import string

import aiohttp
from AWSLoginHandler.common import generate_state
from fastapi import Request, status


class OAuthManager:
    async def get_new_access_token(self, refresh_token: str):
        form_data = aiohttp.FormData(
            fields={"grant_type": "refresh_token", "refresh_token": refresh_token}
        )
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.refresh_url, data=form_data
            ) as server_response:
                response = await server_response.text()
                response = json.loads(response)
                server_status = server_response.status

        if server_status == status.HTTP_200_OK:
            access_token = response["access_token"]
            refresh_token = response["refresh_token"]
        else:
            access_token = refresh_token = None

        return access_token, refresh_token
