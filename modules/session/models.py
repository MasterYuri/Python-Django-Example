"""
Данная модель расширяет стандартный токен авторизации.
Она содержит информацию об устройстве, которое запросило создание токена.
Ипользуется связь OneToOneField:
https://docs.djangoproject.com/pt-br/1.10/topics/db/examples/one_to_one/
"""

from datetime import datetime, timedelta

from django.db import models
from knox import crypto
from knox.crypto import hash_token
from knox.models import AuthToken
from knox.settings import CONSTANTS, knox_settings
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import get_authorization_header

from v1.core.enums import DevicePlatformEnum


class TokenExtended(models.Model):

    class Meta:
        db_table = 'tokens_extended'

    # Know не хранит сам токен, потому связываем по полю digest
    token_digest = models.OneToOneField(
        AuthToken,
        # Если удалится AuthToken то с ним удалиться и TokenExtended.
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='ex',
    )

    platform = models.CharField(max_length=16)
    udid = models.CharField(max_length=1024)
    push_token = models.CharField(max_length=1024, null=True)
    lang = models.CharField(max_length=12, null=True)

    # Данные для refresh токена:
    refresh_digest = models.CharField(
        max_length=CONSTANTS.DIGEST_LENGTH,
        null=True,
        blank=True)
    refresh_salt = models.CharField(
        max_length=CONSTANTS.SALT_LENGTH,
        null=True,
        blank=True,
        unique=True)
    refresh_expires = models.DateTimeField(null=True, blank=True)

    def delete(self, *args, **kwargs):
        super(TokenExtended, self).delete(*args, **kwargs)
        # TODO Удалять весь связанный с токеном кэш (редис)
        pass

    def _init_refresh_token(self):
        refresh_token = crypto.create_token_string()
        refresh_salt = crypto.create_salt_string()
        refresh_digest = crypto.hash_token(refresh_token, refresh_salt)

        refresh_expires = self.token_digest.expires
        if refresh_expires:
            refresh_expires += timedelta(hours=24 * 7)

        self.refresh_digest = refresh_digest
        self.refresh_salt = refresh_salt
        self.refresh_expires = refresh_expires
        self.save()

        return refresh_token

    @classmethod
    def get_token_obj(cls, token):
        """
        Получить объект токена, зная саму строку токена.
        Данный код по сути взять из исходников knox.
        Так как токен не хранится в открытом виде,
        то используется такой сложный поиск,
        что является сомнительным подходом в плане производительности.
        """
        ret = None
        for auth_token in AuthToken.objects.all():
            digest = crypto.hash_token(token, auth_token.salt)
            if digest == auth_token.digest:
                ret = auth_token
                break
        return ret

    @classmethod
    def get_token_obj_by_refresh_token(cls, refresh_token):
        """
        Получить объект токена, зная строку refresh токена.
        """
        ret = None
        for auth_token in AuthToken.objects.all():
            digest = crypto.hash_token(
                refresh_token, auth_token.ex.refresh_salt)
            if digest == auth_token.ex.refresh_digest:
                ret = auth_token
                break
        return ret

    @classmethod
    def get_token_from_request(cls, request):
        """
        Извлекаем из запроса строку токена.
        Реализация во многом скопирована из /knox/auth.py
        """
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'token':
            return None

        if len(auth) == 2:
            return str(auth[1])
        return None

    @classmethod
    def create_token(
            cls,
            user,
            platform,
            udid,
            lang,
            push_token=None,
            expire_hours=None):
        """
        Создаём токен + рефреш токен
        """
        token_str = AuthToken.objects.create(user=user)
        token = TokenExtended.get_token_obj(token_str)
        extended = TokenExtended.objects.create(
            token_digest=token,
            platform=platform,
            push_token=push_token,
            udid=udid,
            lang=lang)

        if expire_hours:  # Обязательно должно идти до _init_refresh_token()
            expire_hours = min(
                abs(expire_hours),
                settings.AUTH_TOKEN_EXPIRE_HOURS)
            token.expires = timezone.now() + timedelta(hours=expire_hours)
            token.save()

        refresh_token_str = extended._init_refresh_token()

        return (token, token_str, refresh_token_str)
