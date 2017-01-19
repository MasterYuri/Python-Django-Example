"""
Здесь переопределена часть функционала knox авторизации
"""

from datetime import datetime, timedelta

from knox.crypto import hash_token
from knox.models import AuthToken
from knox.auth import TokenAuthentication as KnoxTokenAuthentication
from django.utils import translation
from django.utils import timezone

from v1.session.models import TokenExtended
from v1.logger.models import ApiLog
from v1.user.models import User
from v1.core.exceptions import InvalidAuthToken, AuthTokenExpired


class TokenAuthentication(KnoxTokenAuthentication):

    def authenticate(self, request):
        # Нам приходится переопределять данный метод из knox,
        # чтобы инициализировать текущий язык из текущей сессии.
        user_auth_tuple = super(
            TokenAuthentication,
            self).authenticate(request)
        if user_auth_tuple is None:
            return None

        user, token = user_auth_tuple

        # Инициализируем некоторые данные логгера
        # todo

        # Инициализируем текущий язык через сессию
        if token.ex.lang is not None:
            translation.activate(token.ex.lang)
            # Если активен LocaleMiddleware
            request.LANGUAGE_CODE = translation.get_language()

        return (user, token)

    def authenticate_credentials(self, token):
        # Нам приходится переопределять данный метод из knox, потому что
        # knox удаляет токен, а он нам ещё нужен,
        # чтобы использовать refresh token (если он задан).
        # Потому мы удаляем по полю ex.refresh_expires.
        for auth_token in AuthToken.objects.all():
            if auth_token.ex.refresh_expires is not None:
                if auth_token.ex.refresh_expires < timezone.now():
                    auth_token.delete()
                    continue
            elif auth_token.expires is not None:
                if auth_token.expires < timezone.now():
                    auth_token.delete()
                    continue

            digest = hash_token(token, auth_token.salt)
            if digest == auth_token.digest:
                if (auth_token.expires is not None and
                        auth_token.expires < timezone.now()):
                    raise AuthTokenExpired()
                return self.validate_user(auth_token)
        raise InvalidAuthToken()
