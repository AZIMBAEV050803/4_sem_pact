DEFAULT_PORT = 1



def ask_port():
    while True:
        value = input('Введите порт сервера, введите 0 - это значение по умолчанию: ')
        if value != '0':
            try:
                port = int(value)
            except ValueError:
                print('Введенное вами значение является некорректным')
            else:
                return port
        else:
            return DEFAULT_PORT