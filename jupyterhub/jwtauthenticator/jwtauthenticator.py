from jupyterhub.handlers import LogoutHandler, BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
import jwt
from tornado import (
    gen,
    web,
)
from traitlets import (
    Bool,
    List,
    Unicode,
)
from urllib import parse
from auth.dl_authorizer import authenticate_token

class JSONWebTokenLoginHandler(BaseHandler):
    async def get(self):
        header_name = self.authenticator.header_name
        param_name = self.authenticator.param_name

        auth_header_content = self.request.headers.get(header_name, "") if header_name else None
        auth_param_content = self.get_argument(param_name, default="") if param_name else None

        username_claim_field = self.authenticator.username_claim_field
        extract_username = self.authenticator.extract_username
        audience = self.authenticator.expected_audience
        allowed_algorithms= self.authenticator.algorithms
        auth_service_url= self.authenticator.auth_service_url

        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
            _url = next_url
            if param_name:
                auth_param_content = parse.parse_qs(parse.urlparse(next_url).query).get(param_name, "")
                if isinstance(auth_param_content, list):
                    auth_param_content = auth_param_content[0]

        if bool(auth_header_content) + bool(auth_param_content) > 1:
            raise web.HTTPError(400)
        elif auth_header_content:
            token = auth_header_content
        elif auth_param_content:
            token = auth_param_content
        else:
            return self.auth_failed()

        try:
            claims = self.verify_jwt_with_claims(token, auth_service_url, audience, allowed_algorithms)
        except jwt.exceptions.InvalidTokenError:
            return self.auth_failed()

        username = self.retrieve_username(claims, username_claim_field, extract_username=extract_username)
        user = await self.auth_to_user({'name': username})
        self.set_login_cookie(user)

        self.redirect(_url)

    def auth_failed(self):
            raise web.HTTPError(401)

    @staticmethod
    def verify_jwt_with_claims(token, auth_service_url, audience, allowed_algorithms):
        if not audience:
            return authenticate_token(token, auth_service_url, "", allowed_algorithms)
        else:
            return authenticate_token(token, auth_service_url, audience, allowed_algorithms)

    @staticmethod
    def retrieve_username(claims, username_claim_field, extract_username):
        username = claims["content"][username_claim_field]
        if extract_username:
            if "@" in username:
                return username.split("@")[0]
        return username

class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """
    auth_service_url = Unicode(
        config=True,
        help="""Auth service URL to get public keys""")

    header_name = Unicode(
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    param_name = Unicode(
        config=True,
        help="""The name of the query parameter used to specify the JWT token""")

    algorithms = List(
        default_value=['RS256'],
        config=True,
        help="""Specify which algorithms you would like to permit when validating the JWT""")

    username_claim_field = Unicode(
        default_value='username',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    extract_username = Bool(
        default_value=True,
        config=True,
        help="""
        Set to true to split username_claim_field and take the part before the first `@`
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    def get_handlers(self, app):
        print("call get_handler function")
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()

