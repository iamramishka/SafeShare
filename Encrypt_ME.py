import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def aes_encrypt():
    """Encrypts the input text using AES."""
    plain_text = entry_plain_text.get("1.0", tk.END).strip()
    secret_key = entry_secret_key.get().strip()

    if not (16 <= len(secret_key) <= 30):
        messagebox.showerror("Error", "Your secret key must be between 16 and 30 characters.\nExample: abcdefg123456xyz")
        return

    try:
        key = secret_key.ljust(32)[:32].encode('utf-8')  # Pad or trim the key to 32 bytes
        cipher = AES.new(key, AES.MODE_ECB)
        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_text)
        encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')

        entry_encrypted_output.delete("1.0", tk.END)
        entry_encrypted_output.insert("1.0", encrypted_base64)
        show_status("✅ Encryption Successful! Your message is now hidden.", "green")
    except Exception as e:
        show_status("❌ Encryption Failed! Please check your inputs.", "red")


def aes_decrypt():
    """Decrypts the encrypted text using AES and copies the decrypted text to the clipboard."""
    encrypted_text = entry_encrypted_text.get("1.0", tk.END).strip()
    secret_key = entry_decrypt_key.get().strip()

    if not (16 <= len(secret_key) <= 30):
        messagebox.showerror("Error", "Your secret key must be between 16 and 30 characters.\nExample: abcdefg123456xyz")
        return

    try:
        key = secret_key.ljust(32)[:32].encode('utf-8')  # Pad or trim the key to 32 bytes
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_bytes = base64.b64decode(encrypted_text)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        decrypted_text = decrypted_bytes.decode('utf-8')

        # Display the decrypted text in the output field
        entry_decrypted_output.delete("1.0", tk.END)
        entry_decrypted_output.insert("1.0", decrypted_text)

        # Copy the decrypted text to the clipboard
        root.clipboard_clear()
        root.clipboard_append(decrypted_text)
        root.update()

        show_status("✅ Decryption Successful! Text copied to clipboard.", "green")
    except ValueError:
        messagebox.showerror("Error", "❌ Incorrect Secret Key! Please enter the correct key.")
        show_status("❌ Decryption Failed! Wrong Key Entered.", "red")
    except Exception as e:
        show_status("❌ Decryption Failed! Please check your inputs.", "red")


def show_status(message, color):
    """Displays status messages in the UI."""
    status_label.config(text=message, fg=color)
    status_label.after(5000, lambda: status_label.config(text=""))


def toggle_secret_key(entry, toggle_button):
    """Toggles visibility of the secret key input."""
    if entry.cget("show") == "*":
        entry.config(show="")  # Make text visible
        toggle_button.config(text="🔓")  # Open lock icon
    else:
        entry.config(show="*")  # Hide text
        toggle_button.config(text="🔒")  # Closed lock icon


def copy_secret_key(entry):
    """Copies the secret key to the clipboard."""
    root.clipboard_clear()
    root.clipboard_append(entry.get())
    root.update()
    show_status("✅ Secret Key Copied!", "blue")


def paste_secret_key(entry):
    """Pastes the secret key from the clipboard."""
    try:
        entry.delete(0, tk.END)
        entry.insert(0, root.clipboard_get())
        show_status("✅ Secret Key Pasted!", "blue")
    except tk.TclError:
        show_status("❌ No text in clipboard!", "red")


def export_encrypted_text():
    """Exports the encrypted text to a .txt file."""
    encrypted_text = entry_encrypted_output.get("1.0", tk.END).strip()
    if not encrypted_text:
        messagebox.showerror("Error", "No encrypted text available to export!")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Encrypted Text"
    )
    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write(encrypted_text)
            show_status(f"✅ Encrypted text saved to {file_path}!", "blue")
        except Exception as e:
            show_status("❌ Failed to save the file. Please try again.", "red")


def upload_encrypted_text():
    """Uploads a .txt file and pastes its content into the encrypted text field."""
    file_path = filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Upload Encrypted Text"
    )
    if file_path:
        try:
            with open(file_path, "r") as file:
                encrypted_text = file.read().strip()
            entry_encrypted_text.delete("1.0", tk.END)
            entry_encrypted_text.insert("1.0", encrypted_text)
            show_status(f"✅ Encrypted text loaded from {file_path}!", "blue")
        except Exception as e:
            show_status("❌ Failed to load the file. Please try again.", "red")


# Create GUI Window
root = tk.Tk()
root.title("AES Encryption/Decryption Tool")
root.geometry("1200x900")
root.resizable(True, True)
root.configure(bg="#f4f4f4")

style = ttk.Style()
style.configure("TNotebook.Tab", font=("Arial", 14, "bold"))

tab_control = ttk.Notebook(root, style="TNotebook")
tab_encrypt = ttk.Frame(tab_control)
tab_decrypt = ttk.Frame(tab_control)
tab_control.add(tab_encrypt, text="AES Encryption")
tab_control.add(tab_decrypt, text="AES Decryption")
tab_control.pack(expand=True, fill="both")

### Encryption Tab ###
tk.Label(tab_encrypt, text="AES Encryption", font=("Arial", 20, "bold")).pack(pady=10)

tk.Label(tab_encrypt, text="Enter Plain Text to Encrypt:", font=("Arial", 14, "bold")).pack()
entry_plain_text = tk.Text(tab_encrypt, height=10, width=90, wrap="word")
entry_plain_text.pack(pady=5)

tk.Label(tab_encrypt, text="Enter Secret Key (16-30 chars):", font=("Arial", 14, "bold")).pack()
frame_encrypt_key = tk.Frame(tab_encrypt)
frame_encrypt_key.pack()
entry_secret_key = tk.Entry(frame_encrypt_key, width=60, show="*")
entry_secret_key.pack(side=tk.LEFT)
toggle_encrypt_key_button = tk.Button(frame_encrypt_key, text="🔒", command=lambda: toggle_secret_key(entry_secret_key, toggle_encrypt_key_button))
toggle_encrypt_key_button.pack(side=tk.LEFT, padx=5)
copy_encrypt_key_button = tk.Button(frame_encrypt_key, text="📋 Copy", command=lambda: copy_secret_key(entry_secret_key))
copy_encrypt_key_button.pack(side=tk.LEFT, padx=5)

encrypt_button = tk.Button(
    tab_encrypt, text="Encrypt", command=aes_encrypt, bg="#007bff", fg="white", width=20, font=("Arial", 14, "bold")
)
encrypt_button.pack(pady=10)

export_button = tk.Button(
    tab_encrypt, text="Export to File", command=export_encrypted_text, bg="#17a2b8", fg="white", width=20, font=("Arial", 14, "bold")
)
export_button.pack(pady=10)

tk.Label(tab_encrypt, text="AES Encrypted Output:", font=("Arial", 14, "bold")).pack()
entry_encrypted_output = tk.Text(tab_encrypt, height=10, width=90, wrap="word")
entry_encrypted_output.pack(pady=5)

### Decryption Tab ###
tk.Label(tab_decrypt, text="AES Decryption", font=("Arial", 20, "bold")).pack(pady=10)

tk.Label(tab_decrypt, text="Enter AES Encrypted Text:", font=("Arial", 14, "bold")).pack()
entry_encrypted_text = tk.Text(tab_decrypt, height=10, width=90, wrap="word")
entry_encrypted_text.pack(pady=5)

upload_button = tk.Button(
    tab_decrypt, text="Upload File", command=upload_encrypted_text, bg="#ffc107", fg="black", width=20, font=("Arial", 14, "bold")
)
upload_button.pack(pady=10)

tk.Label(tab_decrypt, text="Enter Secret Key (16-30 chars):", font=("Arial", 14, "bold")).pack()
frame_decrypt_key = tk.Frame(tab_decrypt)
frame_decrypt_key.pack()
entry_decrypt_key = tk.Entry(frame_decrypt_key, width=60, show="*")
entry_decrypt_key.pack(side=tk.LEFT)
toggle_decrypt_key_button = tk.Button(frame_decrypt_key, text="🔒", command=lambda: toggle_secret_key(entry_decrypt_key, toggle_decrypt_key_button))
toggle_decrypt_key_button.pack(side=tk.LEFT, padx=5)
paste_decrypt_key_button = tk.Button(frame_decrypt_key, text="📋 Paste", command=lambda: paste_secret_key(entry_decrypt_key))
paste_decrypt_key_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(
    tab_decrypt, text="Decrypt", command=aes_decrypt, bg="#28a745", fg="white", width=20, font=("Arial", 14, "bold")
)
decrypt_button.pack(pady=10)

tk.Label(tab_decrypt, text="AES Decrypted Output:", font=("Arial", 14, "bold")).pack()
entry_decrypted_output = tk.Text(tab_decrypt, height=10, width=90, wrap="word")
entry_decrypted_output.pack(pady=5)

status_label = tk.Label(root, text="", font=("Arial", 14, "bold"), bg="#f4f4f4")
status_label.pack(pady=10)

root.mainloop()
