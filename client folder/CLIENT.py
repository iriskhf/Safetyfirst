import socket
import threading
import tkinter as tk
import codecs

HOST = '192.168.1.207'
PORT = 80

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((HOST, PORT))
print("Connected to server...")

# Create the Tkinter window
window = tk.Tk()
window.title("Safety_First")
window.config(bg="skyblue")
window.geometry("500x500")

#left_frame = tk.Frame(window, width=300, height=300)
#left_frame.grid(row=0, column=0, padx=10, pady=5)

# Add the borders and the computer image
top_border_label = tk.Label(window, text="SAFETYFIRST", font=("Arial", 24))
top_border_label.pack(side="top", fill="x")
#grid(row=1, column=0, padx=5, pady=5)

# Add the input and output places
input_label = tk.Label(window, text="Enter URL", font=("Arial", 14))
input_label.pack(pady=20)
input_entry = tk.Entry(window, font=("Arial", 14))
input_entry.pack(pady=10)

output_label = tk.Label(window, text="", font=("Arial", 14))
output_label.pack(pady=20)


def exit_window():
    client_socket.sendall(codecs.encode("{quit}", 'rot13').encode())
    client_socket.close()
    output_label.config(text=f"Closed connection to server")
    window.destroy()
    print("disconnected from server...")

def clear_input_output():
    input_entry.delete(0, tk.END)
    output_label.config(text=f"")

# Define a function to receive messages from the server
def send_message():
    # Keep receiving messages until the server closes the connection
    message = input_entry.get()
    encoded_message = codecs.encode(message, 'rot13')
    # Send the user's message to the server
    client_socket.sendall(encoded_message.encode())
    # Create a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

    # Clear the input entry
    input_entry.delete(0, tk.END)

def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024).decode()
            decoded_response = codecs.decode(response, 'rot13')
            if response =="try again":
                output_label.config(text=f"{decoded_response}")
                send_message()
            elif not decoded_response:
                output_label.config(text="no response from server, closing connection")
                client_socket.close()
                break
            elif decoded_response=="This url is safe!":
                output_label.config(text=decoded_response,fg="green")
                break
            elif decoded_response=="his url is most likely safe!":
                output_label.config(text=decoded_response,fg="blue")
                break
            elif decoded_response=="This url is suspicious!" or decoded_response=="This url is dangerous!":
                output_label.config(text=decoded_response,fg="red")
            else:
                output_label.config(text=f"{decoded_response}")

        except socket.error as e:
            output_label.config(text=f"Error: {e}")
            client_socket.close()

exit_button = tk.Button(window, text="Exit", command=exit_window)
exit_button.pack(pady=30)

clear_button = tk.Button(window, text="clear", command=clear_input_output)
clear_button.pack(pady=30)

send_button = tk.Button(window, text="Send", font=("Arial", 14), command=send_message)
send_button.pack(pady=10)
# Start a thread to receive messages from the server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Start the Tkinter event loop
window.mainloop()
