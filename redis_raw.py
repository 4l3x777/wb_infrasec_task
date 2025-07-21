import socket

def raw_redis_info(host='127.0.0.1', port=6379):
    # RESP-запрос "INFO"
    payload = b'*1\r\n$4\r\nINFO\r\n'

    with socket.create_connection((host, port), timeout=3) as sock:
        sock.sendall(payload)
        response = sock.recv(4096)  # Можно увеличить размер буфера

    print("Raw Redis response:\n", response.decode(errors='ignore'))

raw_redis_info()