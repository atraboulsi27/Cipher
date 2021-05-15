from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
from tkinter import *
from asymmetric import *

def EncryptAction():
    return

def DecryptAction():
    return

def browse_button():
    # Allow user to select a directory and store it in global var
    # called folder_path
    global folder_path
    if(i.get()==1):
        filename = filedialog.askdirectory()
    else:
        filename = filedialog.askopenfilename()
    folder_path.set(filename)
def error(msg):
    messagebox.showerror("Error", msg)

def Success(msg):
    messagebox.showinfo("Status", message=msg)

def Browse_desitnation_pair_directory():
    directory_name=filedialog.askdirectory()
    pair_generation_directory.set(directory_name)
    return

def GeneratePairAction():
    name=pair_name.get()
    password=pair_pass_.get()
    confirmation=pair_pass_conf.get()
    directory=pair_generation_directory.get()
    if (password==confirmation and password!="" and directory!=""):
        status=create_and_store(password,name,directory)
    else:
        error("failed to create pair, passwords do not match or one of the fields is still empty")
        pair_name.set("")
        pair_pass_.set("")
        pair_pass_conf.set("")
        pair_generation_directory.set("")
        return
    if (status=="Success"):
        Success("Pair Generated Successfully")
    else:
        error(status)
        return
    pair_name.set("")
    pair_pass_.set("")
    pair_pass_conf.set("")
    pair_generation_directory.set("")
    return

def Browse_directory_public_key():
    directory_name=filedialog.askdirectory()
    public_key_directory_path.set(directory_name)
    return
def Browse_public_key_file():
    file_name=filedialog.askopenfilename()
    public_key_file_path.set(file_name)
    return
def Browse_public_key_file_to_encrypt():
    file_name=filedialog.askopenfilename()
    public_key_file_to_encrypt.set(file_name)
    return

def Public_key_encrypt():
    public_key_file=public_key_file_path.get()
    filename=public_key_file_to_encrypt.get()
    envelope_name=Envelope_name.get()
    directory=public_key_directory_path.get()
    encrypted_filename=public_key_encrypted_file_name.get()
    if (public_key_file!="" and filename!="" and envelope_name!="" and directory!="" and encrypted_filename!=""):
        status=envelope_encryption(public_key_file, filename, envelope_name, directory,encrypted_filename)
    else:
        error("failed to encrypt, one of the fields is still empty")
        return

    if (status=="Success"):
        Success("Encrypted file Successfully")
    else:
        error(status)
        return
    public_key_file_path.set("")
    public_key_file_to_encrypt.set("")
    Envelope_name.set("")
    public_key_directory_path.set("")
    public_key_encrypted_file_name.set("")
    return

def Browse_private_key_file():
    file_name=filedialog.askopenfilename()
    private_key_file_path.set(file_name)
    return
def Browse_private_key_file_to_decrypt():
    file_name=filedialog.askopenfilename()
    private_key_file_to_decrypt.set(file_name)
    return

def Browse_envelope():
    file_name=filedialog.askopenfilename()
    Private_Envelope_name.set(file_name)
    return

def Browse_directory_private_key():
    directory_name=filedialog.askdirectory()
    private_key_directory_path.set(directory_name)
    return
def Private_key_decrypt():
    private_key_file=private_key_file_path.get()
    password=private_key_password.get()
    filename=private_key_file_to_decrypt.get()
    envelope_name=Private_Envelope_name.get()
    decrypted_filename=private_key_decrypted_file_name.get()
    directory=private_key_directory_path.get()
    if (private_key_file!="" and password!="" and filename!="" and envelope_name!="" and decrypted_filename!="" and directory!=""):
        status=envelope_decryption(private_key_file, password, filename, envelope_name,directory,decrypted_filename)
    else:
        error("Failed to encrypt, one of the fields is still empty")
        return
    if (status=="Success"):
        Success("Decrypted file Successfully")
    else:
        error(status)
        return
    private_key_file_path.set("")
    private_key_file_to_decrypt.set("")
    Private_Envelope_name.set("")
    private_key_password.set("")
    private_key_decrypted_file_name.set("")
    private_key_directory_path.set("")
    return
root = Tk()
root.title("Security")
root.geometry('1100x700')
root.resizable(width=False, height=False)
tabControl = ttk.Notebook(root)

tab0 = ttk.Frame(tabControl)
tab1 = ttk.Frame(tabControl)
tab2 = ttk.Frame(tabControl)
tab3 = ttk.Frame(tabControl)
tab4 = ttk.Frame(tabControl)
tabControl.add(tab0, text ='Symmetric Encryption')
tabControl.add(tab1, text ='Symmetric Decryption')
tabControl.add(tab2, text ='Create Public-Private Key Pair')
tabControl.add(tab3, text ='Public Key Encrpytion')
tabControl.add(tab4, text ='Private Key Decrpytion')
tabControl.pack(expand = 1, fill ="both")

##Tab 0







##Tab 1
folder_path = StringVar()
folder_path.set("")

#!!!!: Make Compatible for Files. Use Radios for options

#Textbox and button to insert filepath
folderBox = ttk.Entry(tab1, width = 75, textvariable = folder_path).place(x=300,y=70)
button_browse = ttk.Button(tab1,text="Browse", command=browse_button).place(x=800,y=68)
#Radio buttons for folders and files
i = IntVar() 
i.set(1)
r1 = ttk.Radiobutton(tab1, text="Folders", value=1, variable=i).place(x=300,y=100)
r2 = ttk.Radiobutton(tab1, text="Files", value=2, variable=i).place(x=400,y=100)
#Encryption and Decryption buttons
button_encrypt = ttk.Button(tab1,text="Encrypt", command=EncryptAction).place(x=370,y=135)
button_decrypt = ttk.Button(tab1,text="Decrypt", command=DecryptAction).place(x=650,y=135)



####Tab 2
pair_name = StringVar()
pair_name.set("")
pair_pass_ = StringVar()
pair_pass_.set("")
pair_pass_conf = StringVar()
pair_pass_conf.set("")
pair_generation_directory = StringVar()
pair_generation_directory.set("")

label = ttk.Label(tab2, text ="Enter Pair Name").place(x=20,y=40)
pair_name_box = ttk.Entry(tab2, width=35, textvariable = pair_name)
pair_name_box.place(x=130,y=40)
label = ttk.Label(tab2, text ="Enter Password").place(x=20,y=65)
pair_pass_box = ttk.Entry(tab2, width=35, textvariable = pair_pass_)
pair_pass_box.place(x=130,y=65)
pair_pass_box.config(show="*")

label = ttk.Label(tab2, text ="Confirm Password").place(x=20,y=85)
pair_conf_pass_box = ttk.Entry(tab2, width=35, textvariable=pair_pass_conf)
pair_conf_pass_box.place(x=130,y=85)
pair_conf_pass_box.config(show="*")

label_pair_directory = ttk.Label(tab2, text ="Destination Directory").place(x=20,y=105)
public_key_directory = ttk.Entry(tab2, width = 75, textvariable = pair_generation_directory).place(x=300,y=105)
select_public_key_directory = ttk.Button(tab2,text="Select Destination Directory", command=Browse_desitnation_pair_directory).place(x=800,y=105)
button_decrypt = ttk.Button(tab2,text="Generate", command=GeneratePairAction).place(x=20,y=125)



####Tab 3
public_key_file_path = StringVar()
public_key_file_path.set("")
public_key_directory_path = StringVar()
public_key_directory_path.set("")
public_key_file_to_encrypt = StringVar()
public_key_file_to_encrypt.set("")
Envelope_name = StringVar()
Envelope_name.set("")
public_key_encrypted_file_name = StringVar()
public_key_encrypted_file_name.set("")
label_public_key_file = ttk.Label(tab3, text ="Public Key File").place(x=100,y=70)
public_key_file = ttk.Entry(tab3, width = 75, textvariable = public_key_file_path).place(x=300,y=70)
select_public_key_file = ttk.Button(tab3,text="Select Public Key File", command=Browse_public_key_file).place(x=800,y=68)
label_public_key_directory = ttk.Label(tab3, text ="Destination Directory").place(x=100,y=90)
public_key_directory = ttk.Entry(tab3, width = 75, textvariable = public_key_directory_path).place(x=300,y=90)
select_public_key_directory = ttk.Button(tab3,text="Select Destination Directory", command=Browse_directory_public_key).place(x=800,y=88)
file_to_encrypt_public = ttk.Entry(tab3, width = 75, textvariable = public_key_file_to_encrypt).place(x=300,y=120)
label_file_to_encrypt_public = ttk.Label(tab3, text ="File to Encrypt").place(x=100,y=120)
select_file_to_encrypt_public = ttk.Button(tab3,text="Select File to Encrypt", command=Browse_public_key_file_to_encrypt).place(x=800,y=118)
label_envelope_name = ttk.Label(tab3, text ="Enter Desired Envelope Name").place(x=100,y=142)
envelope_name_box = ttk.Entry(tab3, width=35, textvariable=Envelope_name).place(x=300,y=140)
label_encrypted_file_name_public = ttk.Label(tab3, text ="Enter Desired Encrypted file Name").place(x=100,y=162)
encrypted_file_name_public_box = ttk.Entry(tab3, width=35, textvariable=public_key_encrypted_file_name).place(x=300,y=160)
button_public_key_encrypt = ttk.Button(tab3,text="Encrypt", command=Public_key_encrypt).place(x=300,y=180)



####Tab 4
private_key_file_path = StringVar()
private_key_file_path.set("")
private_key_password= StringVar()
private_key_password.set("")
private_key_file_to_decrypt = StringVar()
private_key_file_to_decrypt.set("")
Private_Envelope_name = StringVar()
Private_Envelope_name.set("")
private_key_decrypted_file_name = StringVar()
private_key_decrypted_file_name.set("")
private_key_directory_path = StringVar()
private_key_directory_path.set("")

abel_private_key_file = ttk.Label(tab4, text ="Private Key File").place(x=100,y=70)
private_key_file = ttk.Entry(tab4, width = 75, textvariable = private_key_file_path).place(x=300,y=70)
select_private_key_file = ttk.Button(tab4,text="Select Private Key File", command=Browse_private_key_file).place(x=800,y=68)
label_private_key_password = ttk.Label(tab4, text ="Password").place(x=100,y=90)
private_key_password_box = ttk.Entry(tab4, width = 75, textvariable = private_key_password)
private_key_password_box.place(x=300,y=90)
private_key_password_box.config(show="*")
file_to_decrypt_private = ttk.Entry(tab4, width = 75, textvariable = private_key_file_to_decrypt).place(x=300,y=120)
label_file_to_decrypt_private = ttk.Label(tab4, text ="File to Decrypt").place(x=100,y=120)
select_file_to_decrypt_private= ttk.Button(tab4,text="Select File to Decrypt", command=Browse_private_key_file_to_decrypt).place(x=800,y=118)
label_envelope_name_private = ttk.Label(tab4, text ="Envelope").place(x=100,y=142)
envelope_name_private = ttk.Entry(tab4, width=75, textvariable=Private_Envelope_name).place(x=300,y=140)
select_envelope_private= ttk.Button(tab4,text="Select Envelope", command=Browse_envelope).place(x=800,y=138)
label_decrypted_file_name_private = ttk.Label(tab4, text ="Enter Desired Decrypted file Name").place(x=100,y=162)
decrypted_file_name_private_box = ttk.Entry(tab4, width=35, textvariable=private_key_decrypted_file_name).place(x=300,y=160)
label_private_key_directory = ttk.Label(tab4, text ="Destination Directory").place(x=100,y=180)
private_key_directory = ttk.Entry(tab4, width = 75, textvariable = private_key_directory_path).place(x=300,y=180)
select_pivate_key_directory = ttk.Button(tab4,text="Select Destination Directory", command=Browse_directory_private_key).place(x=800,y=180)
button_private_key_decrypt = ttk.Button(tab4,text="Decrypt", command=Private_key_decrypt).place(x=300,y=200)

root.mainloop()  
