# Пример документации к проекту

* Основные понятия
* Паспорт проекта
* Последние изменения

## Сервер

* Развёртывание и запуск
* Необходимые стандартные модули
* Ежедневные cron скрипты

## Серверному разработчику

* Архитектура
* Данные серверов
* Deploy

## Клиенсткому разработчкиу

* Данные серверов
* Тестовые данные для MOCK
* Чтение логов

### Запросы

* Выполнение запросов
* Работа с сессией
* Мультиязычность

### Ошибки

* Общая структура
* Список

### Валидаторы

* Что это такое
* Список

### Перечисления

* Что это такое
* Список

### Типы данных

* [User / Пользователь](types/user)

### Авторизация и пользователь

* [Авторизация в качестве гостя](api/v1/sessions/guest/_post)
* [Авторизация пользователем](api/v1/sessions/user/_post)
* [Обновить истекшую сессию](api/v1/sessions/refreshed/_post)
* [Изменение данных сессии](api/v1/sessions/current/_patch)
* [Логаут](api/v1/sessions/current/_delete)
* [Логаут для всех сессий](api/v1/sessions/_delete)