from datetime import datetime, timedelta

from django.conf import settings
from django.utils.translation import ugettext as _
from django.contrib.auth.models import AnonymousUser
from knox.models import AuthToken

from v1.api.appview import AppApiView
from v1.core.exceptions import InvalidRefreshToken
from v1.core.reqsponse import Reqsponse
from v1.user.models import User

from ..models import TokenExtended
from ..session import Session


class TokenRefreshed(AppApiView):

    # Чтобы не было ошибки когда в заголовках не передан токен
    throttle_classes = ()
    permission_classes = ()

    def post(self, request, format=None):
        """
        Обновить текущий токен через refresh token.
        """
        req = Reqsponse(request)

        # Получение и валидация данных

        req.check_required_all(['refresh_token'])

        refresh_token_str = req.get_str('refresh_token')
        expire_hours = req.get_float('expire_hours')

        # Обработка

        old_token = TokenExtended.get_token_obj_by_refresh_token(
            refresh_token_str)
        if old_token is None:
            raise InvalidRefreshToken()

        # Создаём новый токен на основе старого
        token, token_str, refresh_token_str = TokenExtended.create_token(
            user=old_token.user,
            platform=old_token.ex.platform,
            udid=old_token.ex.udid,
            lang=old_token.ex.lang,
            push_token=old_token.ex.push_token,
            expire_hours=expire_hours
        )

        # Перемещаем все данные сессии со старого токена на новый
        Session.move_datа_to_token(old_token, token)

        old_token.delete()

        result = {'token': token_str, 'refresh_token': refresh_token_str}

        return req.output(result)
