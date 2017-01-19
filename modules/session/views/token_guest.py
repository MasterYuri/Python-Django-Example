from datetime import datetime, timedelta

from django.conf import settings
from django.utils.translation import ugettext as _
from django.contrib.auth.models import AnonymousUser
from knox.models import AuthToken

from v1.api.appview import AppApiView
from v1.core.exceptions import ObjectNotFound
from v1.core.validators import DevicePlatform, UserDeviceID, AppLang
from v1.core.reqsponse import Reqsponse
from v1.user.models import User

from ..models import TokenExtended


class TokenGuests(AppApiView):

    # Объявляем, чтобы не было ошибки когда в заголовках не передан токен
    throttle_classes = ()
    permission_classes = ()

    def post(self, request, format=None):
        """
        Получение текущего токена.
        """
        param_titles = {
            'platform': _(u'Платформа'),
            'udid': _(u'Идентификатор устройства'),
            'lang': _(u'Язык'),
            'expire_hours': _(u'Период истечения часов'),
        }
        req = Reqsponse(request, param_titles)

        # Получение и валидация данных

        req.check_required_all(['platform', 'udid'])

        if req.get_str('email') and req.get_str('password'):
            raise InputValidationError(msgDev='Сработала защита. Если вы \
                авторизуетесь пользователем, используейте /api/v1/auth/user')

        platform = req.get_str('platform', DevicePlatform)
        udid = req.get_str('udid', UserDeviceID)
        lang = req.get_str('lang', AppLang)
        expire_hours = req.get_float('expire_hours')

        # Обработка

        token, token_str, refresh_token_str = TokenExtended.create_token(
            user=User.get_guest_user(),
            platform=platform,
            udid=udid,
            lang=lang,
            expire_hours=expire_hours)

        result = {'token': token_str, 'refresh_token': refresh_token_str}

        return req.output(result)
