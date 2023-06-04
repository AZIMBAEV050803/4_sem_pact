import random
import socket
from Protocol import DH_Endpoint
from Port import Port

HOST = '127.0.0.1'
pool = Port(10)
PORT = pool.get_port()

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)

print(f'Прослушивание порта {PORT}')
conn, addr = sock.accept()
print(f'Пользователь {addr} подключился')


# Создание сервера с шифрованием Диффи-Хеллмана
def make_keys(conn):
    # публичные ключи от клиента
    bunch = conn.recv(2054).decode()
    bunch = bunch.split(' ')
    # создаем сервера со связкой ключей: публичные от клиента и рандомный персональный
    serverDH = DH_Endpoint(int(bunch[0]), int(bunch[1]), random.randint(1, 420))
    return serverDH


# Функция проверки наличия публичного ключа клиента в списке разрешенных
def access_check(client_public_key):
    with open('Keys', 'r') as file:
        flag = False
        for line in file:
            if int(line) == client_public_key:
                flag = True
                break
    return flag


serverDH = make_keys(conn)

if access_check(serverDH.client_public_key):
    conn.send('Доступ разрешен'.encode())
    # отправляем частичный ключ сервера (B) клиенту
    server_partial_key = serverDH.generate_partial_key()
    conn.send(str(server_partial_key).encode())
    # получаем частичный ключ от клиента
    client_key_partial = int(conn.recv(1024).decode())
    print(client_key_partial)

    serverDH.generate_full_key(client_key_partial)

    while True:
        # принимаем сообщение от клиента и раскодируем его
        msg = conn.recv(2024).decode()
        dec_msg = serverDH.decrypt_message(msg)
        print(f'Зашифрованное сообщение: {msg} \nРаcшифрованное сообщение: {dec_msg}\n')
        server_msg = input('>>')

        if dec_msg.lower() == 'exit' or server_msg.lower() == 'exit':
            conn.send(serverDH.encrypt_message(server_msg).encode())
            break
        conn.send(serverDH.encrypt_message(server_msg).encode())
    conn.close()
else:
    conn.close()
