from datetime import datetime, timedelta

from django.conf import settings
from django.utils.translation import ugettext as _
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import authenticate
from knox.models import AuthToken

from v1.api.appview import AppApiView
from v1.core.exceptions import ObjectNotFound
from v1.core.validators import UserEmail, DevicePlatform,
from v1.core.validators import UserDeviceID, DevicePushToken, AppLang
from v1.core.reqsponse import Reqsponse
from v1.user.models import User
from v1.user.serializers import UserSerializer

from ..models import TokenExtended


class TokenForRealUser(AppApiView):

    # Объявляем, чтобы не было ошибки когда в заголовках не передан токен
    throttle_classes = ()
    permission_classes = ()

    def post(self, request, format=None):

        param_titles = {
            'email': _(u'E-mail'),
            'password': _(u'Пароль'),
            'platform': _(u'Платформа'),
            'udid': _(u'Идентификатор устройства'),
            'push_token': _(u'Токен push-уведомлений'),
            'lang': _(u'Язык'),
            'expire_hours': _(u'Период истечения часов'),
        }
        req = Reqsponse(request, param_titles)

        # Получение и валидация данных

        # push_token не обязательный потому что его можно задать позднее.
        req.check_required_all(['email', 'password', 'platform', 'udid'])

        email = req.get_str('email', UserEmail)
        # Чтобы избежать глюков, решили без валидации.
        password = req.get_str('password')

        platform = req.get_str('platform', DevicePlatform)
        udid = req.get_str('udid', UserDeviceID)
        push_token = req.get_str('push_token', DevicePushToken)
        lang = req.get_str('lang', AppLang)
        expire_hours = req.get_float('expire_hours')

        # Обработка

        user = authenticate(email=email, password=password)
        if user is None:
            # TODO Следует заменить ошибку на другую
            raise ObjectNotFound(['email', 'password'], _(
                'Не удалось найти пользователя либо неверный пароль'))

        token, token_str, refresh_token_str = TokenExtended.create_token(
            user=user,
            platform=platform,
            udid=udid,
            lang=lang,
            push_token=push_token,
            expire_hours=expire_hours)

        result = {
            'token': token_str,
            'refresh_token': refresh_token_str,
            'user': UserSerializer(user).data}

        return req.output(result)
