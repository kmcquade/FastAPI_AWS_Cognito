import random
import string


def generate_state():
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(10)
    )


def generate_query_params(**kwargs):
    return "&".join([f"{k}={v}" for k, v in kwargs.items()])
