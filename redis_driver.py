import redis

# Подключение (без пароля)
r = redis.Redis(host='127.0.0.1', port=6379)

# Отправка команды
info = r.info()

# Вывод версии Redis
print("Redis version:", info.get("redis_version"))