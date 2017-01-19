from django.conf.urls import url
from . import views


urlpatterns = [
    # POST Получить гостевой токен
    url('^sessions/guest/?$', views.TokenGuests.as_view()),
    # POST Получить токен для реального пользователя
    url('^sessions/user/?$', views.TokenUsers.as_view()),
    # PATCH Править текущий токен
    # DELETE Удалить текущий токен
    url('^sessions/current/?$', views.TokenCurrent.as_view()),
    # POST Обновить токен через refresh token
    url('^sessions/refreshed/?$', views.TokenRefreshed.as_view()),
    # DELETE Удалить все токены текущего пользователя
    url('^sessions/?$', views.TokenAll.as_view()),
]
