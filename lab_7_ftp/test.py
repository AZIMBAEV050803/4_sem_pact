import socket
import time
from settings import *

def auth():
    sock = socket.socket()
    sock.connect((HOST, PORT))
    sock.recv(BUFFER_SIZE)
    sock.send('test'.encode())
    sock.recv(BUFFER_SIZE)
    sock.send('test'.encode())
    sock.recv(BUFFER_SIZE)
    main(sock)


def main(sock):
    tests = [('pwd', '\\'),
             ('ls', ''),
             ('mkdir new_dir', ''),
             ('cd new_dir', ''),
             ('touch new_file', ''),
             ('mv new_file.txt renamed_file.txt', ''),
             ('write renamed_file.txt some text', ''),
             ('cat renamed_file.txt', 'some text'),
             ('rm renamed_file.txt', ''),
             ('cd ~', ''),
             ('rm new_dir', '')]
    for index, test in enumerate(tests):
        request = test[0]
        sock.send(request.encode())
        time.sleep(0.1)
        res = sock.recv(BUFFER_SIZE).decode()
        response = '\n'.join(res.split('\n')[:-1])
        print(f"Тест {index + 1}, {'успех' if test[1] == response else 'неудача'}")
        print(f'Команда: {test[0]}')
        print(f'Ожидаемый результат: {test[1]}')
        print(f'Фактический результат: {response}')
        print('*' * 50 + '\n')


if __name__ == '__main__':
    auth()
