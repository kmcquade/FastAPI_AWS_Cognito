import json
import random
import string
from typing import Any

from fastapi.responses import Response

__all__ = ["PrettyJSONResponse", "generate_state", "generate_query_params"]


class PrettyJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=False, allow_nan=False, indent=4, separators=(", ", ": "),).encode(
            "utf-8"
        )


def generate_state():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(10))


def generate_query_params(**kwargs):
    return "&".join([f"{k}={v}" for k, v in kwargs.items()])
