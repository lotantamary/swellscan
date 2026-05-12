import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    ANTHROPIC_API_KEY: str = os.environ["ANTHROPIC_API_KEY"]
    VIRUSTOTAL_API_KEY: str = os.environ["VIRUSTOTAL_API_KEY"]
    SAFEBROWSING_API_KEY: str = os.environ["SAFEBROWSING_API_KEY"]
    URLSCAN_API_KEY: str = os.environ.get("URLSCAN_API_KEY", "")
    ALLOWED_USERS: set[str] = set(os.environ["ALLOWED_USERS"].split(","))
    OIDC_AUDIENCE: str = os.environ["OIDC_AUDIENCE"]
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


config = Config()
