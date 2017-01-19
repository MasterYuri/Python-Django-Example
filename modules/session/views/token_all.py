from datetime import datetime, timedelta

from django.utils.translation import ugettext as _
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ObjectDoesNotExist
from knox.models import AuthToken

from v1.api.appview import AppApiView
from v1.core.exceptions import ObjectNotFound
from v1.core.validators import DevicePlatform, UserDeviceID, AppLang
from v1.core.reqsponse import Reqsponse
from v1.user.models import User

from ..models import TokenExtended


class TokenAll(AppApiView):

    def delete(self, request, format=None):
        """
        Удалить все активные токены текущего пользователя.
        """
        req = Reqsponse(request)
        user = request.user

        if user is None:
            raise ServerError(
                msgDev='Не удаётся получить пользователя сессии из системы')
        if user.is_guest:
            raise PermissionDenied(
                msgDev='Гость не может удалить все свои токены')

        processed_count = 0
        try:
            for token in user.auth_token_set.all():
                token.delete()
                processed_count += 1
        except ObjectDoesNotExist as e:
            pass

        return req.output({'processed_count': processed_count})
