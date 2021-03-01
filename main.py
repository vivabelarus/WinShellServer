import queue
import os
import socket
import sys
import threading
from queue import Queue

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytearray.fromhex('597133743677397A24432646294A404E635266556A576E5A7234753778214125')
iv = bytearray.fromhex('432A462D4A614E645267556B58703273')
random_prefix_size = 16

SERVER_ADDRESS = ('0.0.0.0', 15970)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(SERVER_ADDRESS)
server_socket.listen(10)
print('server is running, please, press ctrl+c to stop')


def recv_all(connection: socket.socket, size: int):
    data = connection.recv(size)
    if len(data) == 0:
        raise ConnectionResetError()
    while len(data) < size:
        next_part = connection.recv(size - len(data))
        if len(next_part) == 0:
            raise ConnectionResetError()
        data += next_part
    return data


def read_thread_func(connection: socket.socket):
    try:
        while True:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            size = recv_all(connection, 4)
            data = recv_all(connection, int.from_bytes(size, byteorder='little'))
            decrypted = unpad(cipher.decrypt(data), AES.block_size)
            print(decrypted.decode("cp866")[random_prefix_size:], end='')
            sys.stdout.flush()
    except ConnectionResetError:
        print("\r\nConnection closed")


def input_thread_func(command_queue: Queue):
    while True:
        command = input()
        bin_command = os.urandom(random_prefix_size) + bytes(command, encoding='cp866') + b'\r\n'
        command_queue.put(bin_command, True)


def run_server():
    command_queue = Queue()
    input_thread = threading.Thread(target=input_thread_func, args=(command_queue,))
    input_thread.start()
    while True:
        connection, address = server_socket.accept()
        print("new connection from {address}".format(address=address))
        command_queue.queue.clear()
        read_thread = threading.Thread(target=read_thread_func, args=(connection,))
        read_thread.start()
        while True:
            try:
                command = command_queue.get(True, 1)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ct_bytes = cipher.encrypt(pad(command, AES.block_size))
                connection.send((len(ct_bytes)).to_bytes(4, byteorder='little'))
                connection.send(ct_bytes)
            except queue.Empty:
                pass
            if not read_thread.is_alive():
                break
        read_thread.join()


if __name__ == '__main__':
    run_server()


