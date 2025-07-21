
---
# WB InfraSec task 2

## Severity: `CRITICAL`

### Последствия (Impact)

- Полный несанкционированный доступ к Redis, дальнейшее продвижение в инфраструктуре.

### Рекомендации по устранению (Recommendation)

- Ограничить доступ к Redis или использовать защищённый интерфейс
- Установить пароль с помощью `requirepass`.
- Защитить порт 6379 фаерволом (iptables, UFW и т.п.)
- Использовать доступ только через VPN или защищённую внутреннюю сеть
- Не использовать Redis напрямую из внешнего интернета

---

## Установка Nuclei
```GO
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Установка уязвимого контейнера
```BASH
docker run --rm -d --name vuln-redis -p 6379:6379 redis:6.2
```

## Анализ протокола

- Через запрос из `redis_driver.py` анализируем работу протокола REdis Serialization Protocol

    ![alt text](/img/img1.png)

- Смотрим payload, представляем его в виде Data для nuclei

    ![alt text](/img/img2.png)

- В wireshark_proto_analysis.txt подготовили данные для nuclei

- Через запрос из `redis_raw.py` тестируем raw запрос '*1\r\n$4\r\nINFO\r\n'

## Пишем шаблон Nuclei no code

- Отправка команды `INFO` в формате RESP (`*1\r\n$4\r\nINFO\r\n`)
- Проверка ответа на наличие строки `redis_version:` (признак успешного доступа)
- Отсутствие ошибки `NOAUTH` в ответе, значит Redis открыт

```yaml
id: redis-unauth-access

info:
  name: Redis Unauthenticated Access
  author: 4l3x777
  severity: critical
  description: |
    Checks if unauthenticated access to Redis is possible by sending the INFO command and looking for the redis_version key in the response.
  tags: network,redis,unauth

network:
  - inputs:
      - data: "*1\r\n$4\r\nINFO\r\n"
        read: 1024
        name: redis-info-response
    matchers:
      - type: word
        part: redis-info-response
        words:
          - "redis_version"
```

## Валидируем

```BASH
nuclei -t redis-unauth-access.yaml -validate
```

## Тестируем

```BASH
nuclei -u redis://127.0.0.1:6379 -t redis-unauth-access.yaml -v
```

## Пишем шаблон Nuclei code

```yaml
id: redis-unauth-access-code

info:
  name: Redis Unauthenticated Access By Python (Code Protocol)
  author: 4l3x777
  severity: critical
  description: |
    Checks if unauthenticated access to Redis is possible by sending the INFO command and looking for the redis_version key in the response.
  tags: redis,unauth,code,python

code:
  - engine:
      - python3
    source: |
      import sys, socket
      # Чтение цели из STDIN
      target = sys.stdin.read().strip()
      host, port = target.split(":")[0], int(target.split(":")[1]) if ':' in target else 6379
      payload = b'*1\r\n$4\r\nINFO\r\n'
      try:
          with socket.create_connection((host, port), timeout=3) as s:
              s.sendall(payload)
              response = s.recv(2048)
          output = response.decode(errors='ignore')
          if "redis_version" in output:
              print("redis_version FOUND:", output.splitlines()[0])
          elif "NOAUTH" in output:
              print("Redis requires AUTH")
          else:
              print("No redis_version in response")
      except Exception as e:
          print("Socket error:", e)

    matchers:
      - type: word
        part: response
        words:
          - "redis_version"
```

## Валидируем

```BASH
nuclei -t redis-unauth-access-code.yaml -validate
```

## Тестируем

```BASH
nuclei -u redis://127.0.0.1:6379 -t redis-unauth-access-code.yaml -v
```
