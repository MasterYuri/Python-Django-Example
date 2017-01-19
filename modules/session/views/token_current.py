from datetime import datetime, timedelta

from django.utils.translation import ugettext as _
from django.contrib.auth.models import AnonymousUser
from knox.models import AuthToken

from v1.api.appview import AppApiView
from v1.core.exceptions import ServerError
from v1.core.validators import DevicePushToken
from v1.core.reqsponse import Reqsponse
from v1.user.models import User

from ..models import TokenExtended


class TokenCurrent(AppApiView):

    def patch(self, request, format=None):
        """
        Изменение данных текущего токена.
        """
        param_titles = {
            'push_token': _(u'Токен push-уведомлений'),
            'lang': _(u'Язык'),
        }
        req = Reqsponse(request, param_titles)

        # Получение и валидация данных

        push_token = req.get_str('push_token', DevicePushToken)
        lang = req.get_str('lang', AppLang)

        # Обработка

        token = request.auth
        if token is None:
            raise ServerError(msgDev='Не удаётся получить токен из системы')

        if lang:
            token.ex.lang = lang

        user = request.user
        if user is not None and not user.is_guest:
            if push_token:
                token.ex.push_token = push_token

        token.ex.save()

        return req.output({})

    def delete(self, request, format=None):
        """
        Удаление текущего токена.
        """
        req = Reqsponse(request)

        token = request.auth
        if token is None:
            raise ServerError(msgDev='Не удаётся получить токен из системы')

        token.delete()

        return req.output({})
