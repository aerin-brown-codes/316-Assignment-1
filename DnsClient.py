import socket
import sys

## GLOBAL VARS
SERVER = None
NAME = None
TIMEOUT = 5
MAX_RETRIES = 3
PORT = 53
IS_MAIL_SERVER = False
IS_NAME_SERVER = False

## Command Line Arg Processing
i = 1
while i < len(sys.argv):
    if sys.argv[i] == "-t":
        TIMEOUT = int(sys.argv[i + 1])
        i += 1
    elif sys.argv[i] == "-r":
        MAX_RETRIES = int(sys.argv[i + 1])
        i += 1
    elif sys.argv[i] == "-p":
        PORT = int(sys.argv[i + 1])
        i += 1
    elif sys.argv[i] == "-mx":
        IS_MAIL_SERVER = True
    elif sys.argv[i] == "-ns":
        IS_NAME_SERVER = True
    elif i == len(sys.argv) - 2:
        SERVER = sys.argv[i][1:] # strip leading '@'
    elif i == len(sys.argv) - 1:
        NAME = sys.argv[i]
    i += 1

try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(TIMEOUT)
        address = (SERVER, PORT)

        """
        general gist of talking to server:
        attempts = 1
        while attempts <= MAX_RETRIES:
            client_socket.sendto(message, address)
            try:
                data, location = client_socet.recvfrom(1024)
                break
            except:
                attempts += 1
        """


except socket.timeout:
    print("Connection timed out.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    client_socket.close()
    print("Connection closed.") 