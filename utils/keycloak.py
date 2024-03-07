import requests
from django.conf import settings

KC_SETTINGS = settings.SUBJECT_SOURCES_SETTINGS.get("keycloak")
BASE_URL = KC_SETTINGS.get("BASE_URL").rstrip("/")
BASE_URL_ADMIN = BASE_URL.replace("/auth/realms/", "/auth/admin/realms/")


def kc_connect() -> requests.Session:
    kc_session = requests.Session()
    req = kc_session.post(
        f"{BASE_URL}/protocol/openid-connect/token",
        data={
            "client_id": KC_SETTINGS.get("CLIENT_ID"),
            "client_secret": KC_SETTINGS.get("CLIENT_SECRET"),
            "grant_type": "client_credentials",
        },
    )
    token = req.json().get("access_token")
    kc_session.headers.update({"Authorization": f"Bearer {token}"})

    return kc_session


def kc_get_users_count(session: requests.Session) -> int:
    req = session.get(f"{BASE_URL_ADMIN}/users/count/")
    return req.json()


def kc_get_users(
    session: requests.Session, first: int, page: int
) -> list[dict]:
    req = session.get(f"{BASE_URL_ADMIN}/users/?first={first}&max={page}")
    return req.json()
