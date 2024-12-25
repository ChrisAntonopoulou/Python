import sqlite3  # import SQLite3 to keep data after the program is closed or restarted
import hashlib  # create secure hash functions
import hmac  # function for the creation of message authentication codes
import random  # for random number generation
import re  # regular expressions module for string manipulation
import pandas as pd  # import pandas for data manipulation
import tkinter as tk  # used for GUI
from tkinter import messagebox  # used for pop-up messages


class Padding:
    # function accepts string and returns string 
    def add_random_padding(self, text: str) -> str:
    # generate random padding length between 1 and 5
        padding_length = random.randint(1, 5)
        return text + ''.join(random.choices("αβγδεζηθικλμνξοπρστυφχψω", k=padding_length))
    # adds in the original text the padding and returns the result (greek alphabet)


class HMACGenerator:  # HMAC generation for message integrity
    # constructor accepting the key string parameter
    def __init__(self, key: str):
        self.key = key

    # encodes secret key & message as bytes and creates a new HMAC with SHA256. HMAC is then converted to hex
    def generate(self, message: str) -> str:
        return hmac.new(self.key.encode(), message.encode(), hashlib.sha256).hexdigest()


class DatabaseManager:
    # manages database operations i.e. creation of tables, saving/retrieving messages

    def __init__(self, db_name: str = "messages.db"):
    # initialise database name and create required table it it doesn't exist
        self.db_name = db_name
        self.create_table()  # creates db table when an instance is initialised

    def create_table(self):  # creates connection to sql db
    # connect to SQLite db and create table for storing messages
        connection = sqlite3.connect(self.db_name)
        cursor = connection.cursor()
        cursor.execute('''
     CREATE TABLE IF NOT EXISTS messages(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     message TEXT,
     hash TEXT
     )
     ''')
        connection.commit()
        connection.close()

    def save_message(self, text: str, hash_value: str):
      # save a new message and its HMAC hash to the databse
        connection = sqlite3.connect(self.db_name)
        cursor = connection.cursor()
        cursor.execute("INSERT INTO messages (message, hash) VALUES (?, ?)", (text, hash_value))
        connection.commit()
        connection.close()

    def get_message_history(self):
      # retried stored messages from the db and return them as pandas dataframe
        connection = sqlite3.connect(self.db_name)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM messages")
        messages = cursor.fetchall()
        connection.close()
        return pd.DataFrame(messages, columns=["ID", "Message", "Hash"])
        # converts the list of messages into pandas with columns "ID", "Message" and "Hash"


class MessageEncryption:
    # Handles encryption and processing of messages
    def __init__(self, secret_key: str, db_manager: DatabaseManager):
        self.padding = Padding()
        self.hmac_generator = HMACGenerator(secret_key)
        self.db_manager = db_manager

    def _clean_message(self, sentence: str) -> str:
    # remove non-alphanumeric characters and convert message to lowercase
        return re.sub(r'[^a-zA-Z0-9]', '', sentence).lower()

    def encrypt_message(self, text: str) -> tuple:
    # clean input text removing special characters
        cleaned_text = self._clean_message(text)
    # add random padding to cleaned text
        padded_text = self.padding.add_random_padding(cleaned_text)
    # generate HMAC hash for padded text
        hash_value = self.hmac_generator.generate(padded_text)
    # save padded text and its hash to the db
        self.db_manager.save_message(padded_text, hash_value)
    # return padded text
        return padded_text, hash_value


class MessageEncryptorGUI:
  #GUI for encrypting messages and viewing message history

    def __init__(self, master, encryptor: MessageEncryption):
      # Initialise GUI window and components
        self.master = master
        self.master.title("Message Encryptor")
        self.encryptor = encryptor

        self.message_label = tk.Label(master, text="Enter your message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.result_label = tk.Label(master, text="Encrypted Message:")
        self.result_label.pack()

        self.hash_label = tk.Label(master, text="HMAC Hash:")
        self.hash_label.pack()

        self.history_button = tk.Button(master, text="View Message History", command=self.view_history)
        self.history_button.pack()

    def encrypt_message(self):
      #get the input message from the text field
        message = self.message_entry.get()

        if message:
          #encrypt the message and diplay the results in the GUI
            encrypted_message, hmac_hash = self.encryptor.encrypt_message(message)
            self.result_label.config(text=f"Encrypted Message: {encrypted_message}")
            self.hash_label.config(text=f"HMAC Hash: {hmac_hash}")
            messagebox.showinfo("Success", "Message encrypted and saved to the database.")
        else:
            # show a warning if no message was entered
            messagebox.showwarning("Input Error", "Please enter a message to encrypt.")

    def view_history(self):
        """Displays the message history using Pandas in a new window."""
        history_df = self.encryptor.db_manager.get_message_history()
        if not history_df.empty:
            history_window = tk.Toplevel(self.master)
            history_window.title("Message History")
            history_text = tk.Text(history_window, wrap="word")
            history_text.insert(tk.END, history_df.to_string(index=False))
            history_text.pack(expand=True, fill="both")
        else:
            messagebox.showinfo("History", "No messages in the history.")


# Application Entry Point
if __name__ == "__main__":
  #define a secret key for HMAC generation
    secret_key = "NOMA"  # Secret key for HMAC
    db_manager = DatabaseManager()
    encryptor = MessageEncryption(secret_key, db_manager)

    root = tk.Tk()
    gui = MessageEncryptorGUI(root, encryptor)
    root.mainloop()
