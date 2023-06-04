import shutil

from server import writeLog, send, recv
from settings import *


class FileManager:

    ''' инициализация основных переменных'''
    def __init__(self, sock, conn, login):
        self.socket = sock
        self.connection = conn
        self.login = login
        self.root = os.getcwd()
        if login == ADMIN:
            os.chdir(WORKING_DIRECTORY)
            self.root = WORKING_DIRECTORY
            self.login = '#' + self.login
        self.currentPath = self.root

    ''' проверка на размер директории, для работы с ней'''
    def dirSize(self, path_):
        size = 0
        for path, dirs, files in os.walk(path_):
            for dir_ in dirs:
                size += self.dirSize(os.path.join(path, dir_))
            for file in files:
                size += os.path.getsize(os.path.join(path, file))
        return size

    ''' проверка пути'''
    def checkPath(self, path):
        return self.root in os.path.abspath(path)

    ''' выводит путь текущего каталога'''
    def pwd(self):
        path = os.getcwd().replace(self.root, '')
        if path == '':
            path = '\\'
        return path + '\n'

    ''' выводит содержимое каталога'''
    def ls(self):
        return '\n'.join(os.listdir(self.currentPath)) + '\n'

    ''' изменяет текущий каталог'''
    def cd(self, path):
        if path == '~':
            path = self.root
        if self.checkPath(path) and os.path.isdir(path):
            os.chdir(path)
            self.currentPath = os.path.join(self.currentPath, path)
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' создает каталог'''
    def mkdir(self, path):
        if self.checkPath(path):
            os.mkdir(path)
            if self.dirSize(self.root) > MAX_DIRECTORY_SIZE:
                self.rm(path)
                return LACK_OF_MEMORY + '\n'
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' перемещает или переименовывает файл'''
    def mv(self, source, destination):
        if self.checkPath(source) and self.checkPath(destination) and os.path.exists(os.path.abspath(source)):
            shutil.move(source, destination)
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' копирует файл в директорию'''
    def cp(self, source, destination):
        if self.checkPath(source) and self.checkPath(destination) and os.path.exists(os.path.abspath(source)):
            shutil.copy(source, destination)
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' удаляет директорию или каталог'''
    def rm(self, path):
        if self.checkPath(path) and os.path.exists(os.path.abspath(path)):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' выводит содержимое файла'''
    def cat(self, path):
        if self.checkPath(path) and os.path.exists(os.path.abspath(path)):
            return open(path, 'r', encoding=ENCODING).read() + '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' создает пустой файл'''
    def touch(self, path):
        if self.checkPath(path):
            if not path.endswith('.txt'):
                path += '.txt'
            open(path, 'a', encoding=ENCODING).close()
            if self.dirSize(self.root) > MAX_DIRECTORY_SIZE:
                self.rm(path)
                return LACK_OF_MEMORY + '\n'
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' добавляет текст в файл'''
    def write(self, *args):
        path, text = args[0], ' '.join(args[1:])
        if self.checkPath(path) and os.path.isfile(path):
            tempText = open(path, 'r', encoding=ENCODING).read()
            open(path, 'a', encoding=ENCODING).write(text)
            if self.dirSize(self.root) > MAX_DIRECTORY_SIZE:
                with open(path, 'w', encoding=ENCODING) as file:
                    file.write(tempText.replace(text, '', (tempText.count(text) - 1)))
                    return LACK_OF_MEMORY + '\n'
            return '\n'
        else:
            return INCORRECT_PATH + '\n'

    ''' выводит информацию о памяти'''
    def free(self):
        return f'Всего места: {MAX_DIRECTORY_SIZE}\nСвободно: {MAX_DIRECTORY_SIZE - self.dirSize(self.root)}\n'

    ''' выводит справку по командам'''
    def help(self):
        return 'pwd - выводит путь текущего каталога\n' \
               'ls DIRECTORY- выводит содержимое каталога\n' \
               'cd DIRECTORY- изменяет текущий каталог\n' \
               'mkdir DIRECTORY - создает каталог\n' \
               'rm PATH - удаляет директорию или каталог\n' \
               'mv SOURCE DESTINATION - перемещает или переименовывает файл\n' \
               'cp SOURCE DESTINATION - копирует файл в директорию\n'\
               'cat FILE - выводит содержимое файла\n' \
               'touch FILE - создает пустой файл\n' \
               'write FILE TEXT - добавляет текст в файл\n' \
               'free - выводит информацию о памяти\n' \
               'exit - разрыв соединения с сервером\n' \
               'help - выводит справку по командам\n'
    ''' Заносит все действия в log'''
    def process(self, request):
        command, *args = request.split(' ')
        writeLog(LOG, f"От пользователя {self.root} получено '{request}'")
        try:
            response = self.COMMANDS[command](self, *args)
        except:
            response = 'incorrect request\n'
        writeLog(LOG, f"Пользователю {self.root} отправлено '{response}'")
        return response

    COMMANDS = {
        'pwd': pwd,
        'ls': ls,
        'cd': cd,
        'mkdir': mkdir,
        'rm': rm,
        'mv': mv,
        'cp': cp,
        'cat': cat,
        'touch': touch,
        'write': write,
        'free': free,
        'help': help
    }

'''Подключение файлового менеджера к серверу под данными пользователя'''
def handle(sock, conn, login):
    checkDirectory(login)
    fileManager = FileManager(sock, conn, login)
    send(conn, CORRECT_PASSWORD + '\n' + fileManager.login + '$' + fileManager.pwd()[:-1] + '>')
    writeLog(LOG, f'Пользователь {fileManager.login} авторизовался')
    while True:
        try:
            request = recv(conn)
            if request == 'exit':
                conn.close()
            response = fileManager.process(request)
            send(conn, response)
            send(conn, fileManager.login + '$' + fileManager.pwd()[:-1] + '>')
        except:
            break

    os.chdir(WORKING_DIRECTORY)
    conn.close()

'''Проверка директории'''
def checkDirectory(login):
    login = WORKING_DIRECTORY + SEP + login
    if not os.path.exists(login) or not os.path.isdir(login):
        os.mkdir(login)
    os.chdir(login)
