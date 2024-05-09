import tkinter
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib


def encrypt(t, p):
    hashed_password = hashlib.md5(p.encode()).hexdigest()
    b64_password = base64.b64encode(hashed_password.encode())
    fernet = Fernet(b64_password)
    return fernet.encrypt(t.encode()).decode()


def decrypt(e, p):
    hashed_password = hashlib.md5(p.encode()).hexdigest()
    b64_password = base64.b64encode(hashed_password.encode())
    fernet = Fernet(b64_password)
    try:
        return fernet.decrypt(e).decode()
    except InvalidToken:
        return None


def select_radiobutton():
    if mode.get() == 1:
        label_text.config(text="Enter plain text")
        button.config(text="Encrypt")
    elif mode.get() == 2:
        label_text.config(text="Enter cipher text")
        button.config(text="Decrypt")
    entry_text.delete(0, 'end')
    entry_key.delete(0, 'end')
    label_status.config(text="")
    entry_text.focus_set()


def runner():
    if mode.get() == 1:
        result = encrypt(text.get(), password.get())
        root.clipboard_clear()
        root.clipboard_append(result)
        label_status.config(text="cipher text copied to clipboard")
    elif mode.get() == 2:
        root.clipboard_clear()
        result = decrypt(text.get(), password.get())
        if result:
            root.clipboard_append(result)
            label_status.config(text="plain text copied to clipboard")
        else:
            label_status.config(text="Invalid key!!!")
    entry_text.delete(0, 'end')
    entry_key.delete(0, 'end')
    entry_text.focus_set()


root = tkinter.Tk()
root.title('PassGuard')
root.geometry('200x180')
root.eval('tk::PlaceWindow . center')
mode = tkinter.IntVar()
text = tkinter.StringVar()
password = tkinter.StringVar()


radiobutton_encrypt = tkinter.Radiobutton(master=root, text="I want to ENCRYPT something", variable=mode, value=1, command=select_radiobutton)
radiobutton_encrypt.grid(column=1, row=1)
radiobutton_encrypt.select()


radiobutton_decrypt = tkinter.Radiobutton(master=root, text="I want to DECRYPT something", variable=mode, value=2, command=select_radiobutton)
radiobutton_decrypt.grid(column=1, row=2)


label_text = tkinter.Label(master=root, text="Enter plain text")
label_text.grid(column=1, row=3)



entry_text = tkinter.Entry(master=root, textvariable=text)
entry_text.grid(column=1, row=4)
entry_text.focus_set()


label_key = tkinter.Label(master=root, text="Enter key")
label_key.grid(column=1, row=5)


entry_key = tkinter.Entry(master=root, textvariable=password, show='*')
entry_key.grid(column=1, row=6)


button = tkinter.Button(master=root, text='Encrypt', command=runner)
button.grid(column=1, row=7)


label_status = tkinter.Label(master=root, text="")
label_status.grid(column=1, row=8)

root.mainloop()
