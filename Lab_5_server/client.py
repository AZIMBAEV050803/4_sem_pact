import socket
from Protocol import DH_Endpoint
from Port import Port

HOST = '127.0.0.1'
pool = Port(10)
PORT = pool.get_port()

sock = socket.socket()
sock.connect((HOST, PORT))

#создание DH клиента
clientDH = DH_Endpoint()
#привязка ключей сервера и клиента
clientDH.bunch_of_public_keys()

keys = str(clientDH.client_public_key)+' '+str(clientDH.server_public_key)

sock.send(keys.encode())


msg = sock.recv(1024).decode()
if msg == 'Доступ разрешен':
    print(msg+'\nЧтобы выйти, отправьте \'exit\'')

    # получаем частичный ключ от сервера
    server_key_partial = int(sock.recv(1024).decode())
    # print(server_key_partial)


    client_partial_key = clientDH.generate_partial_key()
    sock.send(str(client_partial_key).encode())  # отправляем частичный ключ клиента (А) серверу

    # восстанавливаем полный ключ
    clientDH.generate_full_key(server_key_partial)

    while True:
        msg = input('>>')
        if msg.lower() == 'exit':
            sock.send(clientDH.encrypt_message(msg).encode())
            break
        # отправляем закодированное сообщение
        sock.send(clientDH.encrypt_message(msg).encode())
        msg = sock.recv(2024).decode()
        dec_msg = clientDH.decrypt_message(msg)
        print(f'Зашифрованное сообщение: {msg} \nРаcшифрованное сообщение: {dec_msg}\n')
    sock.close()

else:
    print('Доступ запрещен')
    sock.close()
