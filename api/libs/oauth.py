import urllib.parse
from dataclasses import dataclass
from typing import Optional, Callable

import requests


@dataclass
class OAuthUserInfo:
    id: str
    name: str
    email: str


class OAuth:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        raise NotImplementedError()

    def get_access_token(self, code: str):
        raise NotImplementedError()

    def get_raw_user_info(self, token: str):
        raise NotImplementedError()

    def get_user_info(self, token: str) -> OAuthUserInfo:
        raw_info = self.get_raw_user_info(token)
        return self._transform_user_info(raw_info)

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        raise NotImplementedError()


class GitHubOAuth(OAuth):
    _AUTH_URL = "https://github.com/login/oauth/authorize"
    _TOKEN_URL = "https://github.com/login/oauth/access_token"
    _USER_INFO_URL = "https://api.github.com/user"
    _EMAIL_INFO_URL = "https://api.github.com/user/emails"

    def get_authorization_url(self, invite_token: Optional[str] = None):
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "user:email",  # Request only basic user information
        }
        if invite_token:
            params["state"] = invite_token
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get("access_token")

        if not access_token:
            raise ValueError(f"Error in GitHub OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str):
        headers = {"Authorization": f"token {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        user_info = response.json()

        email_response = requests.get(self._EMAIL_INFO_URL, headers=headers)
        email_info = email_response.json()
        primary_email: dict = next((email for email in email_info if email["primary"] == True), {})

        return {**user_info, "email": primary_email.get("email", "")}

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        email = raw_info.get("email")
        if not email:
            email = f"{raw_info['id']}+{raw_info['login']}@users.noreply.github.com"
        return OAuthUserInfo(id=str(raw_info["id"]), name=raw_info["name"], email=email)


class GoogleOAuth(OAuth):
    _AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    _TOKEN_URL = "https://oauth2.googleapis.com/token"
    _USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

    def get_authorization_url(self, invite_token: Optional[str] = None):
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid email",
        }
        if invite_token:
            params["state"] = invite_token
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get("access_token")

        if not access_token:
            raise ValueError(f"Error in Google OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str):
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        return response.json()

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        return OAuthUserInfo(id=str(raw_info["sub"]), name="", email=raw_info["email"])


# ====== Start Add Standard OAuth ======
# GPA Modify 2025-03-04
class StandardOAuth(OAuth):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        auth_url: str,
        token_url: str,
        user_info_url: str,
        scope: str = "openid email",
        transform: Optional[Callable[[dict], OAuthUserInfo]] = None,
    ):
        """
        :param auth_url: authorization endpoint URL
        :param token_url: token endpoint URL
        :param user_info_url: user info endpoint URL
        :param scope: OAuth scope
        :param transform: custom user info transformation function
        """
        super().__init__(client_id, client_secret, redirect_uri)
        self.auth_url = auth_url
        self.token_url = token_url
        self.user_info_url = user_info_url
        self.scope = scope
        self._custom_transform = transform

    def get_authorization_url(self, invite_token: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": self.scope,
        }
        if invite_token:
            params["state"] = invite_token
        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str) -> str:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(self.token_url, data=data, headers=headers)
        if response.status_code != 200:
            print(response.text)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError(f"Error in Standard OAuth, Access Token not found: {token_data}")
        return access_token

    def get_raw_user_info(self, token: str) -> dict:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(self.user_info_url, headers=headers)
        response.raise_for_status()
        return response.json()

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        if self._custom_transform:
            return self._custom_transform(raw_info)
        user_id = raw_info.get("sub") or raw_info.get("id")
        name = raw_info.get("name") or ""
        email = raw_info.get("email") or ""
        return OAuthUserInfo(id=str(user_id), name=name, email=email)

# ====== End Add Standard OAuth ======
