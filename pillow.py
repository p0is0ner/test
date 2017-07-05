import socket
import re
import crypter
import threading
from adapter import Adapter


adapter = Adapter()

print('888888b.   888                   888       .d8888b.  888               888 \n'
      '888  "88b  888                   888      d88P  Y88b 888               888 \n'
      '888  .88P  888                   888      888    888 888               888 \n'
      '8888888K.  888  8888b.   .d8888b 888  888 888        88888b.   8888b.  888888 \n'
      '888  "Y88b 888     "88b d88P"    888 .88P 888        888 "88b     "88b 888 \n'
      '888    888 888 .d888888 888      888888K  888    888 888  888 .d888888 888 \n'
      '888   d88P 888 888  888 Y88b.    888 "88b Y88b  d88P 888  888 888  888 Y88b. \n'
      '8888888P"  888 "Y888888  "Y8888P 888  888  "Y8888P"  888  888 "Y888888  "Y888 \n\n'
      'azerty123456/ Linux / RSA secured TCP chat software, for all CLI lovers <3\n')


class Server:
    def __init__(self, port, interface, max_connections):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((interface, port))
        self.interface = str(interface)
        self.port = int(port)
        self.max_connections = int(max_connections)

        self.online_users = {}  # online users (ip:username)
        self.online_conns = {}  # storing conn (socket objects) for sending data (conn:addr (ip))
        self.trusted_conns = []  # trusted conns (authenticated) for the entire session
        self.banned = []  # banned users

        self.path = '/home/robot/Bureau/python/blackchat'  # will replace this by os method later
        self.private_key = 'private.pem'
        self.public_key = 'public.pem'

        self.client_headers = {
            'AUTH': 'auth',
            'CONN': 'conn',
            'PING': 'ping',
            'PM': 'pm',
            'GETPBK': 'getpbk',
            'GETUSRS': 'GETUSRS',
            'DATA': 'data',
            'CLOSE': 'close',
            'NEWUSR': 'newusr',
        }

        self.server_headers = {
            'AUTH': 'auth',
            'YES': 'yes',
            'NO': 'no',
            'PING': 'ping',
            'CLOSE': 'close',
            'KILL': 'kill',
            'GETUSRS': 'getusrs',
            'GETPBK': 'getpbk',
            'NOAUTH': 'noauth',
            'PMERR': 'pmerr'
        }

    def main_filter(self, buffer):
        for header in self.client_headers.keys():
            out = re.match(re.compile("^(" + header + ")(.+)$"), buffer)
            if out:
                out = list(out.groups())
                if len(out) > 1:
                    return True
                else:
                    return False
            return 'error'

    def no_params_filter(self, buffer):
        for header in self.client_headers.keys():
            # check all headers
            output = re.match(re.compile("^(" + header + ")$"), buffer)
            # checking if the header is in the buff and also if it's
            # the only word in it (header with no params needed)
            return header if output else False

    def params_filter(self, buffer):
        for header in self.client_headers.keys():
            output = re.match(re.compile("^(" + header + ")(.+)$"), buffer)
            if output:
                return list(output.groups())

    def broadcast(self, sender, data):
        for connection, ip in self.online_conns.items():

            if connection != sender:
                public_key_receiver = adapter.fetch_account(ip)
                data = crypter.encrypt_rsa_data(public_key_receiver, data)

                try:
                    connection.send(data)
                except socket.error:
                    connection.close()
                    del self.online_conns[connection]
                    print('[0] connection broken with [{0}] closing...\n'.format(ip))
                return True

    def private_message(self, sender, data, receiver):
        for connection, ip in self.online_conns.items():

            if connection != sender and self.online_users[ip] == receiver:
                public_key_receiver = adapter.fetch_account(ip)
                data = crypter.encrypt_rsa_data(public_key_receiver, data)

                try:
                    connection.send(data)
                    return True
                except socket.error:
                    connection.close()
                    del self.online_conns[connection]
                    print('[0] connection broken with [{0}] closing...\n'.format(ip))
                    return False
            return 'error'

    def main(self):
        print('[0] server bound successfully, now listening on [{0}:{1}] :)\n'.format(self.interface, self.port))

        if adapter.create_table():
            print('[0] creating a database :)\n')

        print('[0] generating set of RSA keys to handle encryption service :)\n')
        crypter.generate_rsa_keys()
        print('[0] RSA keys have been generated and loaded successfully :)\n')

        server_private_key, server_public_key, public_key_to_send = crypter.load_rsa_private_key(), crypter.load_rsa_public_key(), crypter.key_to_send()

        for ip in adapter.all_cons_fetch():
            self.trusted_conns.append(ip[0])

        while True:
            self.socket.listen(self.max_connections)

            conn, addr = self.socket.accept()
            user_ip, user_port = addr[0], addr[1]
            ban = 0

            if user_ip in self.trusted_conns:  # user already authenticated for the session, no need of auth header
                conn.send(self.server_headers['NOAUTH'].encode())

            print('[0] new connection from [{0}:{1}] \n'.format(user_ip, user_port))

            try:
                received_buffer = conn.recv(1024)
            except:
                conn.close(); print('[!] broken connection with [{0}:{0}]\n'.format(user_ip, user_port)); break

            if not received_buffer:
                print('[!] closing connection with [{0}:{1}] \n'.format(user_ip, user_port))
                conn.close()
                break

            elif received_buffer:
                print('[0] received buffer {0}:{1}\n'.format(user_ip, received_buffer))

                if len(received_buffer) == 256:  # possibility that it's RSA encrypted data
                    received_buffer = crypter.decrypt_rsa_data(server_private_key, received_buffer)

                    if not received_buffer:  # probably not encrypted data just 256 bits long string spam
                        print('[!] Received malformed header from [{0}:{1}]\n'.format(user_ip, user_port))

                filtered_buffer = self.main_filter(received_buffer)

                if filtered_buffer:
                    params_buffer = self.params_filter(received_buffer)

                    if params_buffer[0] == self.client_headers['CONN'] and user_ip in self.trusted_conns:
                        username, password = params_buffer[1].split()[0], params_buffer[1].split()[1]
                        account_fetching = adapter.fetch_account(username, password)

                        if not account_fetching:
                            print('[!] user [{0}:{1}] failed login process \n'.format(user_ip, user_port))

                        if account_fetching[0][0] == username and account_fetching[0][1] == password:
                            print('[0] user [{0}:{1}] successfully logged in \n'.format(user_ip, user_port))
                            self.online_users[user_ip] = username
                            conn.send(self.server_headers['YES'])

                    if params_buffer[0] == self.client_headers['NEWUSR'] and user_ip in self.trusted_conns:
                        username = params_buffer[1].split()[0]
                        password = params_buffer[1].split()[1]
                        user_pbk = params_buffer[1].split()[2]
                        print('[0] user [{0}:{1}] is creating a new account\n'.format(user_ip, user_port))

                        if adapter.create_account(username, password, user_ip, user_pbk):
                            print('[0] an account has been created successfully\n')
                            self.online_conns[conn] = user_ip
                            self.online_users[user_ip] = username
                            conn.send(self.server_headers['YES'])

                        elif not adapter.create_account(username, password, user_ip, user_pbk):
                            print('[!] an error occurred during the creation of an account :(\n')
                            conn.send(self.server_headers['NO'])

                    if params_buffer[0] == self.client_headers['DATA'] and user_ip in self.trusted_conns:
                        print('[0] user [{0}:{1}] is sending data to all users\n'.format(user_ip, user_port))
                        self.broadcast(conn, params_buffer[1])

                    if params_buffer[0] == self.client_headers['PM'] and user_ip in self.trusted_conns:
                        receiver= params_buffer[1].split()[0]
                        message = params_buffer[1].split()[1]

                        if self.private_message(conn, message, receiver):
                            print('[0] user [{0}:{1}] sent a private message \n'.format(user_ip, user_port))

                        elif self.private_message(conn, message, receiver) == 'error':
                            conn.send(self.server_headers['PMERR'].encode())

                        elif not self.private_message(conn, message, receiver):
                            conn.send(self.server_headers['PMERR'].encode())

                elif not filtered_buffer:
                    # non params header things
                    non_params_buffer = self.no_params_filter(received_buffer)

                    if non_params_buffer == self.client_headers['AUTH']:
                        # variables integration
                        self.trusted_conns.append(user_ip)
                        self.online_conns[conn] = user_ip
                        # user communication
                        print('[0] user [{0}:{1}] authenticated correctly :)\n'.format(user_ip, user_port))
                        conn.send(self.server_headers['YES'])

                    if non_params_buffer == self.client_headers['PING']:
                        print('[0] executing ping test with [{0}:{1}] \n'.format(user_ip, user_port))
                        conn.send(self.server_headers['PING'])

                    if non_params_buffer == self.client_headers['CLOSE']:
                        print('[0] closing connection process with [{0}:{1}] \n'.format(user_ip, user_port))
                        conn.send(self.server_headers['CLOSE'])
                        del self.online_conns[conn]
                        del self.online_users[ip]

                    if non_params_buffer == self.client_headers['GETPBK']:
                        if user_ip in self.online_conns.values():
                            print('[0] sending public key to [{0}:{1}] \n'.format(user_ip, user_port))
                            conn.send((self.server_headers['GETPBK'] + public_key_to_send).encode())
                        else:
                            print('[!] [{0}:{1}] asked for public key without having authentication permissions\n'.format(user_ip, user_port))
                            conn.send(self.server_headers['NO'].encode())

                elif filtered_buffer == 'error':
                    ban += 1

                    if ban == 3:
                        self.banned.append(self.online_conns[conn])
                        del self.online_conns[conn]
                        del self.online_users[ip]
                        conn.shutdown(socket.SHUT_RDWR)

                    pass
