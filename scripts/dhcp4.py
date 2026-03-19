#!/usr/bin/env python3

import random, sys, logging, json, time
logging.getLogger().setLevel(logging.ERROR)

from scapy.config import conf
conf.ipv6_enabled = False
conf.load_layers.remove('sctp')
conf.verb = 0
conf.checkIPaddr = False

from scapy.all import get_if_raw_hwaddr, Ether, IP, UDP, BOOTP, DHCP, srp1, sendp

def getval(lst,fld):
    for p in lst:
        if type(p) is tuple:
            if p[0] == fld:
                return p[1]
    return None

def mac2bin(mac):
    if ':' in mac:
        mac = mac.split(':')
    elif '-' in mac:
        mac = mac.split('-')
    elif len(mac) == 12:
        mac = mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12]
    else:
        raise ValueError('invalid literal for mac2bin()')

    try:
        mac = tuple(map(lambda x: int(x, base=16), mac))
    except ValueError:
        raise ValueError('invalid literal for mac2bin()')

    if len(mac) == 6:
        pass
    elif len(mac) == 3:
        a, b = divmod(mac[0], 0x100)
        c, d = divmod(mac[1], 0x100)
        e, f = divmod(mac[2], 0x100)
        mac = a, b, c, d, e, f
    elif len(mac) == 2:
        a, b_c = divmod(mac[0], 0x10000)
        b, c = divmod(b_c, 0x100)
        d, e_f = divmod(mac[1], 0x10000)
        e, f = divmod(e_f, 0x100)
        mac = a, b, c, d, e, f
    elif len(mac) == 1:
        a_b_c, d_e_f = divmod(mac[0], 0x1000000)
        a, b_c = divmod(a_b_c, 0x10000)
        b, c = divmod(b_c, 0x100)
        d, e_f = divmod(d_e_f, 0x10000)
        e, f = divmod(e_f, 0x100)
        mac = a, b, c, d, e, f
    else:
        raise ValueError('invalid literal for mac2bin()')


    try:
        mac = ''.join(map(chr, mac))
    except ValueError:
        raise ValueError('invalid literal for mac2bin()')

    return mac

class DHCPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

class DHCPTester(object):
    def __init__(self, interface, servers_ids, mac=None, ip=None, timeout=2):
        try:
            fam, self.mac = get_if_raw_hwaddr(interface)
        except IOError:
            raise DHCPError(1, 'Specified interface does not exists')
        self.interface = interface

        if mac:
            try:
                self.mac = mac2bin(mac)
            except ValueError:
                raise DHCPError(2, 'Wrong value of MAC-address')

        self.ip = ip

        if not servers_ids:
            raise DHCPError(9, 'Servers list is empty')

        if isinstance(servers_ids, str):
            servers_ids = [servers_ids]

        self.servers_ids = servers_ids

        if timeout:
            self.timeout = timeout
        else:
            self.timeout = 2

        self.state = 0
        self.server_ip = None  # IP адрес ответившего DHCP сервера

    def discovery(self):
        pktdiscovery = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/\
                       IP(src='0.0.0.0', dst='255.255.255.255')/\
                       UDP(sport=68, dport=67)/\
                       BOOTP(chaddr=self.mac)/\
                       DHCP(options=[('message-type', 'discover'),
                                     'end'])
        pktoffer = srp1(pktdiscovery, timeout=self.timeout, iface=self.interface)

        if pktoffer is None:
            raise DHCPError(3, 'No offer received')

        if getval(pktoffer[DHCP].options, 'message-type') != 2 or \
           getval(pktoffer[DHCP].options, 'server_id') is None or \
           pktoffer[BOOTP].yiaddr is None:
            raise DHCPError(4, 'Invalid offer received')

        self.server_ip = pktoffer[IP].src
        self.server_mac = pktoffer[Ether].src
        self.server_id = getval(pktoffer[DHCP].options, 'server_id')
        self.requested_addr = pktoffer[BOOTP].yiaddr

        if self.servers_ids and self.server_id not in self.servers_ids:
            print (self.server_id)
            raise DHCPError(5, 'Offer from unwanted DHCP-server')

        if self.ip and self.requested_addr != self.ip:
            raise DHCPError(6, 'Unwanted IP offered')

        self.state = 1

    def request(self):
        if self.state < 1:
            self.discovery()

        pktrequest = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/\
                     IP(src='0.0.0.0', dst='255.255.255.255')/\
                     UDP(sport=68, dport=67)/\
                     BOOTP(chaddr=self.mac)/\
                     DHCP(options=[('message-type', 'request'),
                                   ('server_id', self.server_id),
                                   ('requested_addr', self.requested_addr),
                                   'end'])
        pktack = srp1(pktrequest, timeout=self.timeout, iface=self.interface)

        if pktack is None:
            raise DHCPError(7, 'No ack from server')

        if getval(pktack[DHCP].options, 'message-type') != 5:
            raise DHCPError(8, 'Invalid ack received')

        # Обновляем server_ip, если ACK пришел с другого IP (хотя обычно с того же)
        if pktack[IP].src != self.server_ip:
            self.server_ip = pktack[IP].src

        self.state = 2

    def release(self):
        if self.state != 2:
            return

        pktrelease = Ether(src=self.mac, dst=self.server_mac)/\
                     IP(src=self.requested_addr, dst=self.server_ip)/\
                     UDP(sport=68, dport=67)/\
                     BOOTP(chaddr=self.mac, ciaddr=self.requested_addr, xid=random.randint(0, 0xFFFFFFFF))/\
                     DHCP(options=[('message-type', 'release'),
                                   ('server_id', self.server_id),
                                   ('requested_addr', self.requested_addr),
                                   ('client_id', chr(1), self.mac),
                                   'end'])
        sendp(pktrelease, iface=self.interface)

        self.state = 1

    def get_server_ip(self):
        """Возвращает IP адрес ответившего DHCP сервера"""
        return self.server_ip

if __name__ == '__main__':
    unix_time = int(time.time())

    # Проверка минимального количества аргументов (нужен хотя бы интерфейс и список серверов)
    if len(sys.argv) < 3:
        print('{"dhcp": {"result": 100, "time": ' + str(unix_time) + '}}')
        print('Usage: %s <interface> <servers_ids> [<mac> [<ip> [<timeout>]]]' % sys.argv[0], file=sys.stderr)
        print('  servers_ids - comma-separated list of DHCP server IPs (e.g., "192.168.1.32,192.168.1.50")', file=sys.stderr)
        sys.exit(100)

    args = sys.argv[1:]

    # Разбор аргументов
    interface = args[0]

    # Разделяем список серверов по запятой
    servers_ids = args[1].split(',')

    # Опциональные параметры
    mac = None
    ip = None
    timeout = None

    if len(args) > 2:
        mac = args[2]
    if len(args) > 3:
        ip = args[3]
    if len(args) > 4:
        try:
            timeout = int(args[4])
        except ValueError:
            timeout = 2

    server_ip = None

    try:
        dhcp = DHCPTester(interface, servers_ids, mac, ip, timeout)
        dhcp.discovery()
        dhcp.request()
        server_ip = dhcp.get_server_ip()
        dhcp.release()
    except DHCPError as e:
        # В случае ошибки также пытаемся получить server_ip, если он уже был определен
        if dhcp and hasattr(dhcp, 'get_server_ip'):
            server_ip = dhcp.get_server_ip()

        # Формируем JSON с ошибкой, включая server_ip если он есть
        if server_ip:
            dhcp_data = '{"dhcp": {"result": ' + str(e.code) + ', "time": ' + str(unix_time) + ', "server_ip": "' + server_ip + '"}}'
        else:
            dhcp_data = '{"dhcp": {"result": ' + str(e.code) + ', "time": ' + str(unix_time) + '}}'
        print (dhcp_data)
        sys.exit (e.code)

    # Формируем JSON с успешным результатом, включая server_ip
    if server_ip:
        print ('{"dhcp": {"result": 0, "time": ' + str(unix_time) + ', "server_ip": "' + server_ip + '"}}')
    else:
        print ('{"dhcp": {"result": 0, "time": ' + str(unix_time) + '}}')
