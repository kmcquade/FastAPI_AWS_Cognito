from distutils.core import setup

from setuptools import find_packages

try:
    from AWSLoginHandler.version import __version__
except ModuleNotFoundError:
    # I think we always end up here unless we have every necessary package installed (which we don't want to do)
    exec(open("AWSLoginHandler/version.py").read())

setup(
    name="AWSLoginHandler",
    version=__version__,
    packages=find_packages(),
    package_data={p: ["*"] for p in find_packages()},
    url="",
    license="",
    install_requires=[
        "pydantic",
        "fastapi",
        "aiohttp",
        "requests",
        "pyjwt",
        "python-jose[cryptography]",
    ],
    python_requires=">=3.8.0",
    author="Tom.McLean",
    author_email="tom.mclean@bartechnologies.uk",
    description="Helper classes for attaching to a FastAPI app allowing for user login using AWS Cognito",
)
