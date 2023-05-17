import threading
from classcheck import Basiccheckup
from Classcheck3 import Seriouscheckup
import socket
import sqlite3
import codecs

# Set up the server socket
HOST = socket.gethostname()
PORT = 80

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a public host and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()

# Create a list to store all client sockets
client_sockets = []

print("listening to client...")

def handle_client(client_socket, client_address):
    try:
        client_socket.sendall(codecs.encode("Welcome to server!", 'rot13').encode())
        while True:
            # Receive the message from the client
            data = client_socket.recv(1024).decode()
            message = codecs.decode(data, 'rot13')
            if not message:
                print(f"message from {client_address} was empty")
                break

            if message == "{quit}":
                print(f"Received disconnect message from {client_address}.")
                break
            else:
                client_url = message
                client_socket.sendall(codecs.encode(f"Checking {client_url} . . .",'rot13').encode())
                checkup1 = Basiccheckup(client_url, 0,"")
                result = str(checkup1.get_first_report())
                encoded_result = codecs.encode(result, 'rot13')
                if checkup1.urlscore == 100:
                    print(result)

                if checkup1.urlscore == 30:
                    print(result)

                while checkup1.urlscore == 100 or checkup1.urlscore == 30:
                    # Receive a new message from the client
                    client_socket.sendall(encoded_result.encode())
                    #client_socket.sendall(codecs.encode("try again", 'rot13').encode())
                    client_url = codecs.decode(client_socket.recv(1024).decode(), 'rot13')

                    if not client_url:
                        print(f"Client {client_address} has disconnected.")
                        break

                    print(f"Received message from {client_address}: {client_url}")

                    if client_url == "{quit}":
                        print(f"Received disconnect message from {client_address}.")
                        break

                    checkup1 = Basiccheckup(client_url, 0, "")
                    result = str(checkup1.get_first_report())
                    encoded_result = codecs.encode(result, 'rot13')

                    if result == "oops! invalid input":
                        print("invalid client input")
                        continue

                    if checkup1.urlscore == 100:
                        print("invalid client input")
                        #client_socket.sendall(codecs.encode("invalid client input", 'rot13').encode())
                        continue

                    if checkup1.urlscore == 30:
                        print("url already in DB")
                        #client_socket.sendall(codecs.encode("url already in DB", 'rot13').encode())
                        continue


                checkup2 =Seriouscheckup(checkup1.url,checkup1.urlscore,checkup1.report)
                result1 = checkup2.get_second_report()
                score =checkup2.get_final_score()
                result1 += f"final url score: {score}\n"
                print(f"Result: {result1}")
                client_socket.sendall(codecs.encode(result1, 'rot13').encode())

                # Update the database based on the score
                db_lock = threading.Lock()
                try:
                    with db_lock:
                        with sqlite3.connect('URLdatabase.db') as conn:
                            with conn:
                                cursor = conn.cursor()
                                if score == 0:
                                    cursor.execute("SELECT rowid FROM URLtable WHERE safe IS NULL ORDER BY rowid ASC LIMIT 1")
                                    row = cursor.fetchone()
                                    if row is not None:
                                        cursor.execute("UPDATE URLtable SET safe = ? WHERE rowid = ?",(client_url, row[0]))
                                    else:
                                        cursor.execute("INSERT INTO URLtable (safe) VALUES (?)", (client_url,))
                                    client_socket.sendall(codecs.encode("This url is safe!", 'rot13').encode())
                                elif score <= 3:
                                    cursor.execute("SELECT rowid FROM URLtable WHERE most_likely_safe IS NULL ORDER BY rowid ASC LIMIT 1")
                                    row = cursor.fetchone()
                                    if row is not None:
                                        cursor.execute("UPDATE URLtable SET most_likely_safe = ? WHERE rowid = ?",(client_url, row[0]))
                                    else:
                                        cursor.execute("INSERT INTO URLtable (most_likely_safe) VALUES (?)",(client_url,))
                                    client_socket.sendall(codecs.encode("This url is most likely safe!", 'rot13').encode())
                                elif score <= 5:
                                    cursor.execute("SELECT rowid FROM URLtable WHERE suspicious IS NULL ORDER BY rowid ASC LIMIT 1")
                                    row = cursor.fetchone()
                                    if row is not None:
                                        cursor.execute("UPDATE URLtable SET suspicious = ? WHERE rowid = ?",(client_url, row[0]))
                                    else:
                                        cursor.execute("INSERT INTO URLtable (suspicious) VALUES (?)", (client_url,))
                                    client_socket.sendall(codecs.encode("This url is suspicious!", 'rot13').encode())
                                else:
                                    cursor.execute("SELECT rowid FROM URLtable WHERE malicious IS NULL ORDER BY rowid ASC LIMIT 1")
                                    row = cursor.fetchone()
                                    if row is not None:
                                        cursor.execute("UPDATE URLtable SET malicious = ? WHERE rowid = ?",(client_url, row[0]))
                                    else:
                                        cursor.execute("INSERT INTO URLtable (malicious) VALUES (?)", (client_url,))
                                    client_socket.sendall(codecs.encode("This url is dangerous!", 'rot13').encode())

                        print(f"{client_url} added to DB")
                        conn.commit()
                        conn.close()
                except sqlite3.Error as error:
                    print("Error while connecting to SQLite", error)
                    client_socket.sendall(codecs.encode("Error occurred while adding URL to database", 'rot13').encode())


    except ConnectionResetError as e:
        print(f"ConnectionResetError occurred with {client_address}: {e}")
    except Exception as e:
        print(f"An error occurred with {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Client {client_address} has disconnected.")



# Function to handle incoming connections
def handle_incoming_connections():
    while True:
        # Wait for a new client connection
        client_socket, client_address = server_socket.accept()
        print(f"New client connected: {client_address}")

        # Add the new client socket to the list
        client_sockets.append(client_socket)

        # Start a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


# Start a new thread to handle incoming connections
connection_thread = threading.Thread(target=handle_incoming_connections)
connection_thread.start()

#connection_thread.join()
for client_socket in client_sockets:
    client_socket.close()
