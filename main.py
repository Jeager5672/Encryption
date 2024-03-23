from tkinter import *
from tkinter import messagebox
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageTk

image = Image.open("Remove-bg.ai_1708437756203.png")
image = image.resize((150, 150))

window = Tk()
window.title("Secret Notes")
window.minsize(width=400, height=400)
window.config(padx=20, pady=20)

# Görüntüyü Tkinter için uygun hale getirgit
photo = ImageTk.PhotoImage(image)
canvas = Canvas(window, width=200, height=155)
canvas.create_image(100, 100, anchor=CENTER, image=photo)
canvas.pack()

title_label = Label(text="Enter the Title")
title_label.config(fg="black", padx=10, pady=10)
title_label.pack()

title_entry = Entry(width=30)
title_entry.focus()
title_entry.pack()

secret_label = Label(text="Enter the Secret Message")
secret_label.config(fg="black", padx=10, pady=10)
secret_label.pack()

secret_text = Text(width=30, height=10)
secret_text.pack()

masterkey_label = Label(text="Enter the Key")
masterkey_label.config(fg="black", padx=10, pady=10)
masterkey_label.pack()

masterkey_entry = Entry(width=30, show="*")
masterkey_entry.pack()


desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

salt = b'some.secret.salt'
def save_and_encrypt():
    title = title_entry.get()
    secret = secret_text.get("1.0", END)
    streaky = masterkey_entry.get()

    if len(title) == 0 or len(secret) == 0 or len(streaky) == 0:
        messagebox.showerror(title="Error", message="Please fill in all fields.")
    else:
        password = streaky.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        encrypted_text = secret.encode()
        token1 = f.encrypt(encrypted_text).decode()


        with open(os.path.join(desktop_path, "encrypted_notes.txt"), "a") as file:
            file.write(f"Title: {title}\n")
            file.write(f"Encrypted Message: {token1}\n")
            file.write("\n")
            messagebox.showinfo(title="Completed", message="Your note has been saved and encrypted.")

def decrypt_notes():
    # Get the master key from the entry widget
    master_key = masterkey_entry.get()
    title1 = title_entry.get()
    secret1 = secret_text.get("1.0", END)

    # Read the encrypted notes from the file
    with open(os.path.join(desktop_path, "encrypted_notes.txt"), "r") as file:
        lines = file.readlines()

    # Iterate through lines to find the encrypted message corresponding to the title
    encrypted_message = None
    for i in range(0, len(lines), 3):  # Assuming each note is 3 lines (title, encrypted message, blank line)
        title_line = lines[i]
        encrypted_message_line = lines[i + 1]
        if title_line.strip() == f"Title: {title1}" and encrypted_message_line == f"Encrypted Message: {secret1}":
            encrypted_message = encrypted_message_line.split("Encrypted Message: ")[1].strip()
            break

    if encrypted_message is None:
        messagebox.showerror(title="Error", message="Note not found.")
        return

    # Decode the master key and decrypt the message
    try:
        password = master_key.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message.encode()).decode()

        # Show the decrypted message
        messagebox.showinfo(title="Decrypted Message", message=decrypted_message)

    except (InvalidToken, ValueError):
        messagebox.showerror(title="Error", message="Decryption failed. Incorrect master key.")


save_button = Button(text="Save & Encrypt",command=save_and_encrypt)
save_button.config(padx=1, pady=1)
save_button.pack(padx=(10, 0), pady=(10, 0))

decrypt_button = Button(text="Decrypt",command=decrypt_notes)
decrypt_button.config(padx=1, pady=1)
decrypt_button.pack(padx=(10, 0), pady=(10, 0))

window.mainloop()