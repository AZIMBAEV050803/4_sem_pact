import binascii
import hashlib
import json
import os
from datetime import datetime
from hashlib import sha256
from flask import Flask, request, abort, jsonify


app = Flask(__name__)

'''загрузка файла'''
def load():
    with open('auth.json', 'r', encoding='utf-8') as file:
        return list(json.load(file))

'''запись в файл'''
def dump(auth):
    with open('auth.json', 'w', encoding='utf-8') as file:
        file.write(json.dumps(auth))

'''проверка пользователя'''
def checkLogin(login):
    global users
    return login in [user['login'] for user in users]

'''создание запроса на аутентификацию(логин+пароль)'''
def makeResponse(result=True, description=''):
    return {'result': result,
            'description': description}

'''шифратор пароля'''
def hashPassword(password, salt: str = None):
    if salt:
        salt = salt.encode('ascii')
        newPassword = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
        newPassword = binascii.hexlify(newPassword)
        return (salt + newPassword).decode('ascii')
    else:
        salt = sha256(os.urandom(70)).hexdigest().encode('ascii')
        newPassword = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
        newPassword = binascii.hexlify(newPassword)
        return (salt + newPassword).decode('ascii'), salt.decode('ascii')

'''егестрирует пользователя'''
def regUser(user):
    global users
    password, salt = hashPassword(user['password'])
    newUser = {'login': user['login'],
               'password': password,
               'salt': salt,
               'date': datetime.now().isoformat()}
    users.append(newUser)
    dump(users)
    return makeResponse(True, 'пользователь был зарегистрирован в системе'), 201

'''Функция по проверке пароля'''
def checkPassword(user):
    global users
    login = user['login']
    password = user['password']
    try:
        checkedUser = list(filter(lambda x: x['login'] == login, users))[0]
        checkedPassword = checkedUser['password']
        checkedSalt = checkedUser['salt']
        newPassword = hashPassword(password, checkedSalt)
        return checkedPassword == newPassword
    except IndexError:
        return False

'''Проверка на ренистрацию, если пользователь отсутствует, то отсылает к первоначальной функции'''
@app.route('/user/reg', methods=['POST']) # создает ссылку для flask и метод, который применяется(работает только для post)
def regUsers():
    user = json.loads(request.get_data())
    if checkLogin(user['login']):
        return makeResponse(False, 'этот логин уже был зарегистрирован')
    else:
        return regUser(user)

'''Показывает список пользователей'''
@app.route('/user/<string:username>', methods=['GET']) # создает ссылку для flask и метод, который применяется(работает только для get)
def getUser(username):
    try:
        global users
        user = list(filter(lambda x: x['login'] == username, users))[0]
        print('print1 ', user)
        return jsonify({'users': user})
    except IndexError:
        abort(404)

'''Аутентификация'''
@app.route('/users', methods=['GET', 'POST'])
def authUser():
    global users

    if request.method == 'GET':
        return jsonify({'users': users})
    else:
        if checkLogin(json.loads(request.get_data())['login']) and checkPassword(json.loads(request.get_data())):
            return makeResponse(True, 'авторизация прошла успешно')
        elif checkLogin(json.loads(request.get_data())['login']) and not checkPassword(json.loads(request.get_data())) == false:
            return makeResponse(False, 'некорректный пароль')
        else:
            return makeResponse(True, 'некорректное имя пользователя')

'''Базовая страница'''
@app.route('/')
def user_data():
    return 'система регистрации пользователей'


users = load()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
