HOST = '127.0.0.1'
PORT = 80
DIRECTORY = 'index'
BUFFER_SIZE = 8192
DEFAULT_PATH = 'index.html'
ALLOWED_TYPES = ('html',
                 'css',
                 'js',
                 'png')
CODES = {200: 'OK',
         403: 'Forbidden',
         404: 'Not found'}
TYPES = {'html': 'text/html',
         'css': 'text/css',
         'js': 'text/js',
         'png': 'image/png'}
RESPONSE_PATTERN = '''HTTP/1.1 {} {}
Date: {}
Server: SelfMadeServer v0.0.1
Content-Type: {}
Content-Length: {}
Connection: keep-alive

'''
