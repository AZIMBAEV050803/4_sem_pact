import socket
import time
import logging
import json
from port import ask_port


def log_print(st):
    logging.info(st)
    print(st)


logging.basicConfig(filename='server.log', level=logging.INFO)

log_print('Сервер запущен')
port = ask_port()

server = socket.socket()
server.bind(('127.0.0.1', port))
log_print(f'Прослушивание порта {port}')

try:
    while True:
        server.listen(1)

        def open_f(file_name):
            try:
                with open(file_name, 'r') as f:
                    data = json.load(f)
            except:
                with open(file_name, 'w') as f:
                    json.dump({}, f)
                with open(file_name, 'r') as f:
                    data = json.load(f)
            return data


        def record_f(file_name, data):
            try:
                with open(file_name, 'r') as f:
                    data_old = json.load(f)
                data_old.update(data)
                with open(file_name, 'w') as f:
                    json.dump(data_old, f)
            except:
                with open(file_name, 'w') as f:
                    json.dump(data, f)


        def open_t(file_name):
            file = open(file_name, 'r')
            return file


        def record_t(file_name, line):  # Записывает в txt файл
            file = open(file_name, 'a')
            file.write(line + ' ;\n')
            file.close()



        client_socket, address = server.accept()
        right = 1
        try:
            data = open_t('server_list.txt')
        except:
            data = record_t('server_list.txt', '')

        nal = 'NO'
        for i in data:
            if i != ' ;\n':
                if i.split(', ')[2] == address[0]:
                    nal = 'YES'
                    login = i.split(', ')[0]

        client_socket.send(str(nal).encode())
        if nal == 'YES':
            data1 = open_f('passwd.json')
            if data1[login] == client_socket.recv(1024).decode():
                client_socket.send('Пароль верен'.encode())
                log_print(str(address[0]) + ', ' + str(address[1]) + ' подсоединился')
                record_t('server_list.txt', login + ', ' + str(port) + ', ' + str(address[0]) + ', ' + str(address[1]))
            else:
                client_socket.send('Пароль не верен'.encode())
                print('Неудачная попытка подключения')
                log_print(login + ' пытался подключиться')
                right = 0
        else:
            login = client_socket.recv(1024).decode()
            password = client_socket.recv(1024).decode()
            record_f('passwd.json', {login: password})
            record_t('server_list.txt', login + ', ' + str(port) + ', ' + str(address[0]) + ', ' + str(address[1]))
            log_print(str(address[0]) + ', ' + str(address[1]) + ' подсоединился')


        while right:
            client_socket.send('Вы подключены!'.encode())
            try:
                data = client_socket.recv(2048).decode()
            except OSError:
                data = None

            time.sleep(3)
            if data:
                # получение данных от клиента
                log_print(f'\nПолучаем данные от клиента: {data}')

                if data.lower() == 'exit':
                    log_print('Клиент отключился')
                    break
            msg = input('\nВвод текста для клиента:\n').encode()
            # отправка сообщений клиенту
            client_socket.send(msg)
            if msg == 'exit'.encode():
                time.sleep(2)
                # срабатывание команды exit на отключение
                log_print('exit команда получена')
                server.shutdown(socket.SHUT_WR)
                server = socket.socket()
                server.bind(('127.0.0.1', port))
                break

# остановка работы серевера
except KeyboardInterrupt:
    log_print('Сервер отключен')
    server.shutdown(socket.SHUT_WR)
