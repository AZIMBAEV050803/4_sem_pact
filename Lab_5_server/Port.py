class Port:
    def __init__(self, MAX_PORTS):
        self.available_ports = list(range(1000, 1099))
        self.MAX_PORTS = min(MAX_PORTS, len(self.available_ports))

    def get_port(self):
        if self.MAX_PORTS > 0:
            self.MAX_PORTS -= 1
            return self.available_ports.pop(0)
        else:
            raise Exception('Не осталось доступных портов для подключения')


