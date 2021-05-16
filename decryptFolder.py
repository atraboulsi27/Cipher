import sys
from encryption import decryptFolder
from tkinter import ttk
from tkinter import messagebox
from tkinter import *

def show_enc_fun():
    if(show_enc.get() == False ):
        enc_pass_box.config(show="")
        enc_pass_box_conf.config(show="")
        show_enc.set(True)
    else:
        enc_pass_box.config(show="*")
        enc_pass_box_conf.config(show="*")
        show_enc.set(False)

filename = ""
for i in range(len(sys.argv)-1):
	filename = filename + " " + sys.argv[i+1]
filename = filename[1:]

def error(msg):
    messagebox.showerror("Error", msg)

def DecryptAction():

	if enc_pass_.get() != "" and enc_pass_.get() == enc_pass_conf.get():
		decryptFolder(filename,enc_pass_.get())
		root.destroy()

	else:
		error("Passwords don't match!")

	enc_pass_.set("")
	enc_pass_conf.set("")

	return

root = Tk()
root.title("Enter Password")
root.geometry('600x300')
root.resizable(width=False, height=False)

enc_pass_= StringVar()
enc_pass_.set("")
enc_pass_conf= StringVar()
enc_pass_conf.set("")
show_enc = BooleanVar()
show_enc.set(False)

label_pass_enc = ttk.Label(root, text ="Enter Password").place(x=20,y=65)
enc_pass_box = ttk.Entry(root, width=35, textvariable = enc_pass_)
enc_pass_box.place(x=140,y=65)
enc_pass_box.config(show="*")
label_conf_enc= ttk.Label(root, text ="Confirm Password").place(x=20,y=90)
enc_pass_box_conf = ttk.Entry(root, width=35, textvariable=enc_pass_conf)
enc_pass_box_conf.place(x=140,y=90)
enc_pass_box_conf.config(show="*")
button_encrypt = ttk.Button(root,text="Decrypt", command=DecryptAction).place(x=300,y=150)
show_pass_enc = ttk.Checkbutton(root,text="Show Password", command=show_enc_fun).place(x=400,y=65)

root.mainloop()

