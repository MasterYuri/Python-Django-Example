from datetime import datetime, timedelta

from django.conf import settings
from django.conf.urls import url
from django.utils.translation import ugettext as _
from django.utils import timezone
from django.utils.crypto import get_random_string
from knox.models import AuthToken
from rest_framework.request import Request
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest

from v1.core.test import AppTestCase
from v1.user.models import User

from .models import TokenExtended
from .session import Session
from .urls import urls


class AuthTestCase(AppTestCase):

    url_prefix = '/api/v1'

    def make_request_requred_auth(self):
        """
        Данный запрос нужен для проверки разрешения на
        неавторизованные запросы. Если пользователь не
        авторизован (в т.ч. гостем), то он должен приводить
        к InvalidAuthToken.
        """
        return self.jsonGet('/dicts/air_ports/')

    def setUp(self):
        self.logout()

    def test_header_required(self):
        self.make_request_requred_auth()
        self.assertErrorIs('InvalidAuthToken')

        self.loginAsGuest()
        self.make_request_requred_auth()
        self.assertSuccess()

        self.logout()
        self.make_request_requred_auth()
        self.assertErrorIs('InvalidAuthToken')

        self.createUserAndLogin()
        self.make_request_requred_auth()
        self.assertSuccess()

        self.logout()
        self.make_request_requred_auth()
        self.assertErrorIs('InvalidAuthToken')

    def test_auth_guest(self):
        # Не хватает обязательного параметра platform
        authData = {'udid': 'skfjhskjfh21hkhkjfs'}
        response = self.jsonPost('/sessions/guest/', authData)
        # TODO Заменить ошибку на InputValidationError
        self.assertErrorIs('UserInputValidationError')
        self.assertEqual(self.json['params'], ['platform'])

        # Не хватает обязательного параметра udid
        authData = {'platform': 'ios'}
        response = self.jsonPost('/sessions/guest/', authData)
        # TODO Заменить ошибку на InputValidationError
        self.assertErrorIs('UserInputValidationError')
        self.assertEqual(self.json['params'], ['udid'])

        # Кривая платформа
        authData = {'platform': 'blabla', 'udid': 'skfjhskjfh21hkhkjfs'}
        response = self.jsonPost('/sessions/guest/', authData)
        self.assertErrorIs('InputValidationError')
        self.assertEqual(self.json['params'], ['platform'])

        # Кривой язык
        authData = {'platform': 'ios', 'udid': 'skfjhskjfh2k', 'lang': 'xxx'}
        response = self.jsonPost('/sessions/guest/', authData)
        self.assertErrorIs('InputValidationError')
        self.assertEqual(self.json['params'], ['lang'])

        # Всё ОК
        authData = {'platform': 'ios', 'udid': 'skfjhskjfh2k', 'lang': 'en'}
        response = self.jsonPost('/sessions/guest/', authData)
        self.assertSuccess()
        self.assertDictHasKey(self.json, 'token')

        token = TokenExtended.get_token_obj(self.json['token'])
        user = token.user

        self.assertEqual(token.ex.platform, authData['platform'])
        self.assertEqual(token.ex.udid, authData['udid'])

        self.assertEqual(user.is_guest, True)

    def test_auth_user(self):
        try:
            user = cls.objects.get(email='test@test.com').delete()
        except:
            pass
        email = 'test@test.com'
        passw = '12341234'
        authData = {
            'email': email,
            'password': passw,
            'platform': 'ios',
            'udid': 'skfjhskjfh21hkhkjfs'
        }
        # Проверяем требование обязательных параметров
        for key, val in authData.items():
            data = authData.copy()
            del data[key]
            response = self.jsonPost('/sessions/user/', data)
            self.assertEqual(response.status_code, 400)
            # TODO Заменить ошибку на InputValidationError
            self.assertEqual(self.json['key'], 'UserInputValidationError')
            self.assertEqual(self.json['params'], [key])

        authData['push_token'] = 'aaskfjhskjfh21hkhkjfsbb'

        # Всё ОК но невалидный e-mail
        authData['email'] = get_random_string(32)
        response = self.jsonPost('/sessions/user/', authData)
        # TODO Заменить ошибку на InputValidationError
        self.assertErrorIs('UserInputValidationError')
        self.assertEqual(self.json['params'], ['email'])

        # Пользователя не существует
        authData['email'] = email
        response = self.jsonPost('/sessions/user/', authData)
        # TODO Заменить ошибку на другую
        self.assertErrorIs('ObjectNotFound')
        self.assertEqual(self.json['params'], ['email', 'password'])

        # Создаём пользователя
        first_name = 'Ivan'
        last_name = 'Ivanov'
        user = User.objects.create(
            username='ivan' + get_random_string(8),
            first_name=first_name,
            last_name=last_name,
            email=email)
        user.set_password(passw)
        user.save()

        # Пароль не тот
        authData['password'] = get_random_string(32)
        response = self.jsonPost('/sessions/user/', authData)
        # TODO Заменить ошибку на другую
        self.assertErrorIs('ObjectNotFound')
        self.assertEqual(self.json['params'], ['email', 'password'])

        # Всё ОК
        authData['password'] = passw
        response = self.jsonPost('/sessions/user/', authData)
        self.assertSuccess(200)
        self.assertDictHasKey(self.json, 'token')
        self.assertDictHasKey(self.json, 'user')

        self.assertEqual(self.json['user']['id'], user.id)
        self.assertEqual(self.json['user']['first_name'], user.first_name)
        self.assertEqual(self.json['user']['last_name'], user.last_name)

        token = TokenExtended.get_token_obj(self.json['token'])
        u = token.user

        self.assertEqual(token.ex.platform, authData['platform'])
        self.assertEqual(token.ex.udid, authData['udid'])
        self.assertEqual(token.ex.push_token, authData['push_token'])

        self.assertEqual(u.is_guest, False)
        self.assertEqual(u.id, user.id)
        self.assertEqual(u.first_name, user.first_name)
        self.assertEqual(u.last_name, user.last_name)

    def test_logout(self):
        self.loginAsGuest()
        self.assertSuccess()
        token1 = self.json['token']
        tokenObject1 = TokenExtended.get_token_obj(token1)
        digest1 = tokenObject1.digest

        self.loginAsGuest()
        self.assertSuccess()
        token2 = self.json['token']
        tokenObject2 = TokenExtended.get_token_obj(token2)
        digest2 = tokenObject2.digest

        self.useToken(token1)

        # Запросы с токеном проходят всё ОК
        self.make_request_requred_auth()
        self.assertSuccess()

        # Делаем logout, то есть токен невалидным
        response = self.jsonDelete('/sessions/')
        self.assertSuccess()

        # Запросы с этим токеном больше не валидны
        self.make_request_requred_auth()
        self.assertErrorIs('InvalidAuthToken')

        # Но у второго они работают, logout у него не произошел
        self.useToken(token2)
        self.make_request_requred_auth()
        self.assertSuccess()

        # Провереяем что физически токен удалился из обоих таблиц
        try:
            AuthToken.objects.get(digest=digest1)
            self.assertTrue(False)
        except ObjectDoesNotExist as e:
            pass

        try:
            TokenExtended.objects.get(token_digest=digest1)
            self.assertTrue(False)
        except ObjectDoesNotExist as e:
            pass

    def test_edit(self):
        self.loginAsGuest()
        token1 = self.json['token']
        tokenObject1 = TokenExtended.get_token_obj(token1)
        digest1 = tokenObject1.digest

        response = self.jsonPatch('/sessions/', {
            'lang': 'en',
            'push_token': 'f9afa97f6das9ad6f9asfa67967fd9as6'
        })
        self.assertSuccess()
        obj = TokenExtended.get_token_obj(token1)
        self.assertEquals(obj.ex.lang, 'en')
        # Для гостя пуш токен не записыается
        self.assertEquals(obj.ex.push_token, None)

        response = self.jsonPatch('/sessions/', {
            'lang': 'ru',
            'push_token': 'f9afa97f6das9ad6f9asfa67967fd9as6'
        })
        self.assertSuccess()
        obj = TokenExtended.get_token_obj(token1)
        self.assertEquals(obj.ex.lang, 'ru')
        # Для гостя пуш токен не записыается
        self.assertEquals(obj.ex.push_token, None)

        #############

        self.createUserAndLogin()
        token1 = self.json['token']
        tokenObject1 = TokenExtended.get_token_obj(token1)
        digest1 = tokenObject1.digest

        response = self.jsonPatch('/sessions/', {
            'lang': 'en',
            'push_token': 'f9afa97f6das9ad6f9asfa67967fd9as61111'
        })
        self.assertSuccess()
        obj = TokenExtended.get_token_obj(token1)
        self.assertEquals(obj.ex.lang, 'en')
        # Для гостя пуш токен не записыается
        self.assertEquals(
            obj.ex.push_token,
            'f9afa97f6das9ad6f9asfa67967fd9as61111'
        )

        response = self.jsonPatch('/sessions/', {
            'lang': 'ru',
            'push_token': 'f9afa97f6das9ad6f9asfa67967fd9as62222'
        })
        self.assertSuccess()
        obj = TokenExtended.get_token_obj(token1)
        self.assertEquals(obj.ex.lang, 'ru')
        # Для гостя пуш токен не записыается
        self.assertEquals(
            obj.ex.push_token,
            'f9afa97f6das9ad6f9asfa67967fd9as62222'
        )

    def test_logout_all(self):
        # Сначала проверям что гость так делать не может
        self.loginAsGuest()
        self.jsonDelete('/sessions/all/')
        self.assertErrorIs('PermissionDenied')

        # Проверяем для двух пользователей

        # Первый с двумя токенами
        data = self.createUserAndLogin()
        token1 = self.json['token']
        tokenObject1 = TokenExtended.get_token_obj(token1)
        digest1 = tokenObject1.digest

        self.loginAsUser(data['email'], data['password'])
        token2 = self.json['token']
        tokenObject2 = TokenExtended.get_token_obj(token2)
        digest2 = tokenObject2.digest

        self.assertNotEqual(token1, token2)

        # Второй
        data = self.createUserAndLogin()
        token3 = self.json['token']
        tokenObject3 = TokenExtended.get_token_obj(token3)
        digest3 = tokenObject3.digest

        # Проверяем
        self.useToken(token1)
        self.jsonGet('/dicts/air_ports/')
        self.assertSuccess()

        self.useToken(token2)
        self.jsonGet('/dicts/air_ports/')
        self.assertSuccess()

        self.useToken(token3)
        self.jsonGet('/dicts/air_ports/')
        self.assertSuccess()

        # Деавторизуем
        self.loginAsGuest()
        self.useToken(token1)
        self.jsonDelete('/sessions/all/')
        self.assertSuccess()
        self.assertDictKeyIs(self.json, 'processed_count', 2)

        # Проверяем
        self.useToken(token1)
        self.jsonGet('/dicts/air_ports/')
        self.assertErrorIs('InvalidAuthToken')

        self.useToken(token2)
        self.jsonGet('/dicts/air_ports/')
        self.assertErrorIs('InvalidAuthToken')

        self.useToken(token3)
        self.jsonGet('/dicts/air_ports/')
        self.assertSuccess()

    def test_token_expire_for_guest(self):
        self.loginAsGuest()

        token = TokenExtended.get_token_obj(self.auth_token)
        ttl = settings.REST_KNOX['TOKEN_TTL']
        expires_period_min = ttl - timedelta(seconds=10)
        expires_period_max = ttl + timedelta(seconds=10)
        # settings.REST_KNOX['TOKEN_TTL'] = timedelta(hours=expire_hours)
        self.assertTrue(token.expires > timezone.now() + expires_period_min)
        self.assertTrue(token.expires < timezone.now() + expires_period_max)

        # То же самое но передаём своё время жизни
        self.loginAsGuest(expire_hours=2.5)
        self.make_request_requred_auth()
        self.assertSuccess()

        token = TokenExtended.get_token_obj(self.auth_token)
        # 150 минут это 2.5 часа
        expires_period_min = timedelta(minutes=150) - timedelta(seconds=10)
        expires_period_max = timedelta(minutes=150) + timedelta(seconds=10)
        # settings.REST_KNOX['TOKEN_TTL'] = timedelta(hours=expire_hours)
        self.assertTrue(token.expires > timezone.now() + expires_period_min)
        self.assertTrue(token.expires < timezone.now() + expires_period_max)

    def test_token_expire_for_user(self):
        self.createUserAndLogin()

        token = TokenExtended.get_token_obj(self.auth_token)
        ttl = settings.REST_KNOX['TOKEN_TTL']
        expires_period_min = ttl - timedelta(seconds=10)
        expires_period_max = ttl + timedelta(seconds=10)
        # settings.REST_KNOX['TOKEN_TTL'] = timedelta(hours=expire_hours)
        self.assertTrue(token.expires > timezone.now() + expires_period_min)
        self.assertTrue(token.expires < timezone.now() + expires_period_max)

        # То же самое но передаём своё время жизни
        self.createUserAndLogin(expire_hours=2.5)
        self.make_request_requred_auth()
        self.assertSuccess()

        token = TokenExtended.get_token_obj(self.auth_token)
        # 150 минут это 2.5 часа
        expires_period_min = timedelta(minutes=150) - timedelta(seconds=10)
        expires_period_max = timedelta(minutes=150) + timedelta(seconds=10)
        # settings.REST_KNOX['TOKEN_TTL'] = timedelta(hours=expire_hours)
        self.assertTrue(token.expires > timezone.now() + expires_period_min)
        self.assertTrue(token.expires < timezone.now() + expires_period_max)

    def test_bug_get_token_with_expired_token(self):
        """
        Данный тест проверяет следующий баг:
        Когда мы делаем запрос на получение токена,
        но всё равно передаём токен, да ещё и истекший."""
        self.loginAsGuest()

        # Делаем токен истекшим
        token = TokenExtended.get_token_obj(self.auth_token)
        token.expires = timezone.now() - timedelta(seconds=10)
        token.save()

        self.make_request_requred_auth()
        self.assertErrorIs('AuthTokenExpired')

        # Но запрос на получение токена должен работать, даже с этим токеном:
        authData = {
            'platform': 'ios',
            'udid': 'skfjhskjfh21hkhkjfs',
            'lang': 'en'
        }
        response = self.jsonPost('/sessions/guest/', authData)
        self.assertSuccess()
        response = self.jsonPost('/sessions/guest', authData)
        self.assertSuccess()

    def test_refresh_token(self):
        """
        Тестим refresh token гостя.
        TODO Сделать аналогичный запрос для обычного пользователя
        """
        self.loginAsGuest()

        token_str = self.json['token']
        refresh_token_str = self.json['refresh_token']

        request = Request(HttpRequest())
        request.auth = TokenExtended.get_token_obj(token_str)
        session = Session(request)
        session.set('var1', 11)
        session.set('var2', 12)
        self.assertEqual(session.get('var1'), 11)
        self.assertEqual(session.get('var2'), 12)

        self.make_request_requred_auth()
        self.assertSuccess()

        # Делаем токен истекшим
        token = TokenExtended.get_token_obj(self.auth_token)
        token.expires = timezone.now() - timedelta(seconds=10)
        token.save()

        self.make_request_requred_auth()
        self.assertErrorIs('AuthTokenExpired')

        # Данные сессии всё ещё живы
        self.assertEqual(session.get('var1'), 11)
        self.assertEqual(session.get('var2'), 12)

        # Обновляем
        response = self.jsonPost('/sessions/refresh', {
            'refresh_token': refresh_token_str
        })
        self.assertSuccess()
        token_str2 = self.json['token']
        refresh_token_str2 = self.json['refresh_token']
        self.assertNotEquals(token_str, token_str2)
        self.assertNotEquals(refresh_token_str, refresh_token_str2)

        # Данные по старому токену умерли
        self.assertEqual(session.get('var1', None), None)
        self.assertEqual(session.get('var2', None), None)

        # По старому ошибка (он стоит текущим в TestCase)
        self.make_request_requred_auth()
        # Токен уже удален из системы, потому ошибка именно такая
        self.assertErrorIs('InvalidAuthToken')

        # Меняем текущий токен и всё ОК
        self.useToken(token_str2)
        request = Request(HttpRequest())
        request.auth = TokenExtended.get_token_obj(token_str2)
        session = Session(request)

        self.make_request_requred_auth()
        self.assertSuccess()

        # По новой сессии появились наши данные
        self.assertEqual(session.get('var1'), 11)
        self.assertEqual(session.get('var2'), 12)

        # И ещё раз чтобы уж наверняка
        response = self.jsonPost('/sessions/refresh', {
            'refresh_token': refresh_token_str
        })
        self.assertErrorIs('ObjectNotFound')
        response = self.jsonPost('/sessions/refresh', {
            'refresh_token': refresh_token_str2
        })
        self.assertSuccess()
        self.make_request_requred_auth()
        # Токен уже удален из системы, потому ошибка именно такая
        self.assertErrorIs('InvalidAuthToken')

        self.assertEqual(session.get('var1', None), None)
        self.assertEqual(session.get('var2', None), None)
