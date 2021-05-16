from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
from tkinter import *
from asymmetric import *
from encryption import *

#Encrypt or decrypt opens a new window to get password
def EncryptFolder():
    folder_path=folder_path_sym_encryption.get()
    if folder_path == "" :
        error("No folder selected!")
    else:
        password = enc_pass_.get()
        confirmation= enc_pass_conf.get()
        if (password==confirmation and password!=""):
            encryptFolder(folder_path,password)
        else:
            error("Password Error!")
            return
        enc_pass_.set("")
        enc_pass_conf.set("")
        folder_path_sym_encryption.set("")
    return

def DecryptFolder():
    password = dec_pass_.get()
    if folder_path_sym_decryption.get() == "" :
        error("No folder selected !")
    else:
        if password != "":
            decryptFolder(folder_path_sym_decryption.get(),password)
        else:
            error("No password inputed")
        dec_pass_.set("")
        folder_path_sym_decryption.set("")
    return

def EncryptFile():
    folder_path=folder_path_sym_encryption.get()
    if folder_path == "" :
        error("No file selected!")
    else:
        password = enc_pass_.get()
        confirmation= enc_pass_conf.get()
        if (password==confirmation and password!=""):
            encryptFile(folder_path,password)
        else:
            error("Password Error!")
            return
        enc_pass_.set("")
        enc_pass_conf.set("")
        folder_path_sym_encryption.set("")
    return

def DecryptFile():

    folder_path=folder_path_sym_decryption.get()
    if folder_path == "" :
        error("No folder selected!")
    else:
        password = enc_pass_.get()
        if (password!=""):
            decryptFolder(folder_path,password)
        else:
            error("Password Error!")
            return
        dec_pass_.set("")
        folder_path_sym_decryption.set("")
    return

def EncryptAction():

    if i_enc.get() == 1:
        EncryptFolder()
    else:
        EncryptFile()

    return

def DecryptAction():

    if i_dec.get() == 1:
        DecryptFolder()
    else:
        DecryptFile()

    return

def browse_button_encryption():
    # Allow user to select a directory and store it in global var
    # called folder_path
    if(i_enc.get()==1):
        filename = filedialog.askdirectory()
    else:
        filename = filedialog.askopenfilename()

    folder_path_sym_encryption.set(filename)

def show_enc_fun():
    if(show_enc.get() == False ):
        enc_pass_box.config(show="")
        enc_pass_box_conf.config(show="")
        show_enc.set(True)
    else:
        enc_pass_box.config(show="*")
        enc_pass_box_conf.config(show="*")
        show_enc.set(False)
def show_dec_fun():
    if(show_dec.get() == False ):
        dec_pass_box.config(show="")
        show_dec.set(True)
    else:
        dec_pass_box.config(show="*")
        show_dec.set(False)
def show_gen_fun():
    if(show_gen.get() == False ):
        pair_pass_box.config(show="")
        pair_conf_pass_box.config(show="")
        show_gen.set(True)
    else:
        pair_pass_box.config(show="*")
        pair_conf_pass_box.config(show="*")
        show_gen.set(False)

def show_priv_fun():
    if(show_private.get() == False ):
        private_key_password_box.config(show="")
        show_private.set(True)
    else:
        private_key_password_box.config(show="*")
        show_private.set(False)

def browse_button_decryption():
    if(i_dec.get()==1):
        filename = filedialog.askdirectory()
    else:
        filename = filedialog.askopenfilename()
    folder_path_sym_decryption.set(filename)


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

## Tab 0 
folder_path_sym_encryption = StringVar()
folder_path_sym_encryption.set("")
enc_pass_= StringVar()
enc_pass_.set("")
enc_pass_conf= StringVar()
enc_pass_conf.set("")
i_enc = IntVar() 
i_enc.set(1)
show_enc = BooleanVar()
show_enc.set(False)
folderBox_encryption = ttk.Entry(tab0, width = 75, textvariable = folder_path_sym_encryption).place(x=140,y=40)
button_browse_encryption = ttk.Button(tab0,text="Browse", command=browse_button_encryption).place(x=600,y=38.5)
label_pass_enc = ttk.Label(tab0, text ="Enter Password").place(x=20,y=65)
enc_pass_box = ttk.Entry(tab0, width=35, textvariable = enc_pass_)
enc_pass_box.place(x=140,y=65)
enc_pass_box.config(show="*")
label_conf_enc= ttk.Label(tab0, text ="Confirm Password").place(x=20,y=90)
enc_pass_box_conf = ttk.Entry(tab0, width=35, textvariable=enc_pass_conf)
enc_pass_box_conf.place(x=140,y=90)
enc_pass_box_conf.config(show="*")
r1 = ttk.Radiobutton(tab0, text="Folder", value=1, variable=i_enc).place(x=150,y=125)
r2 = ttk.Radiobutton(tab0, text="File", value=2, variable=i_enc).place(x=200,y=125)
button_encrypt = ttk.Button(tab0,text="Encrypt", command=EncryptAction).place(x=300,y=150)
show_pass_enc = ttk.Checkbutton(tab0,text="Show Password", command=show_enc_fun).place(x=400,y=65)


##Tab 1 
folder_path_sym_decryption = StringVar()
folder_path_sym_decryption.set("")
dec_pass_= StringVar()
dec_pass_.set("")
i_dec = IntVar() 
i_dec.set(1)
show_dec = BooleanVar()
show_dec.set(False)
folderBox_decryption = ttk.Entry(tab1, width = 75, textvariable = folder_path_sym_decryption).place(x=140,y=40)
button_browse_decryption = ttk.Button(tab1,text="Browse", command=browse_button_decryption).place(x=600,y=38.5)
label_pass_dec = ttk.Label(tab1, text ="Enter Password").place(x=20,y=65)
dec_pass_box = ttk.Entry(tab1, width=35, textvariable = dec_pass_)
dec_pass_box.place(x=140,y=65)
dec_pass_box.config(show="*")
r3 = ttk.Radiobutton(tab1, text="Folder", value=1, variable=i_dec).place(x=150,y=100)
r4 = ttk.Radiobutton(tab1, text="File", value=2, variable=i_dec).place(x=200,y=100)
button_decrypt = ttk.Button(tab1,text="Decrypt", command=DecryptAction).place(x=200,y=135)
show_pass_dec = ttk.Checkbutton(tab1,text="Show Password", command=show_dec_fun).place(x=400,y=65)

####Tab 2
pair_name = StringVar()
pair_name.set("")
pair_pass_ = StringVar()
pair_pass_.set("")
pair_pass_conf = StringVar()
pair_pass_conf.set("")
pair_generation_directory = StringVar()
pair_generation_directory.set("")
show_gen = BooleanVar()
show_gen.set(False)
label = ttk.Label(tab2, text ="Enter Pair Name").place(x=20,y=40)
pair_name_box = ttk.Entry(tab2, width=35, textvariable = pair_name)
pair_name_box.place(x=140,y=40)
label = ttk.Label(tab2, text ="Enter Password").place(x=20,y=65)
pair_pass_box = ttk.Entry(tab2, width=35, textvariable = pair_pass_)
pair_pass_box.place(x=140,y=65)
pair_pass_box.config(show="*")

label = ttk.Label(tab2, text ="Confirm Password").place(x=20,y=90)
pair_conf_pass_box = ttk.Entry(tab2, width=35, textvariable=pair_pass_conf)
pair_conf_pass_box.place(x=140,y=90)
pair_conf_pass_box.config(show="*")

label_pair_directory = ttk.Label(tab2, text ="Destination Directory").place(x=20,y=115)
public_key_directory = ttk.Entry(tab2, width = 75, textvariable = pair_generation_directory).place(x=140,y=115)
select_public_key_directory = ttk.Button(tab2,text="Select Destination Directory", command=Browse_desitnation_pair_directory).place(x=600,y=112.5)
button_decrypt = ttk.Button(tab2,text="Generate", command=GeneratePairAction).place(x=20,y=140)
show_pass_gen = ttk.Checkbutton(tab2,text="Show Password", command=show_gen_fun).place(x=500,y=65)


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
label_public_key_directory = ttk.Label(tab3, text ="Destination Directory").place(x=100,y=95)
public_key_directory = ttk.Entry(tab3, width = 75, textvariable = public_key_directory_path).place(x=300,y=95)
select_public_key_directory = ttk.Button(tab3,text="Select Destination Directory", command=Browse_directory_public_key).place(x=800,y=92.5)
file_to_encrypt_public = ttk.Entry(tab3, width = 75, textvariable = public_key_file_to_encrypt).place(x=300,y=120)
label_file_to_encrypt_public = ttk.Label(tab3, text ="File to Encrypt").place(x=100,y=120)
select_file_to_encrypt_public = ttk.Button(tab3,text="Select File to Encrypt", command=Browse_public_key_file_to_encrypt).place(x=800,y=118)
label_envelope_name = ttk.Label(tab3, text ="Enter Desired Envelope Name").place(x=100,y=145)
envelope_name_box = ttk.Entry(tab3, width=35, textvariable=Envelope_name).place(x=300,y=145)
label_encrypted_file_name_public = ttk.Label(tab3, text ="Enter Desired Encrypted file Name").place(x=100,y=170)
encrypted_file_name_public_box = ttk.Entry(tab3, width=35, textvariable=public_key_encrypted_file_name).place(x=300,y=170)
button_public_key_encrypt = ttk.Button(tab3,text="Encrypt", command=Public_key_encrypt).place(x=300,y=200)



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
show_private = BooleanVar()
show_private.set(False)
abel_private_key_file = ttk.Label(tab4, text ="Private Key File").place(x=100,y=70)
private_key_file = ttk.Entry(tab4, width = 75, textvariable = private_key_file_path).place(x=300,y=70)
select_private_key_file = ttk.Button(tab4,text="Select Private Key File", command=Browse_private_key_file).place(x=800,y=68)
label_private_key_password = ttk.Label(tab4, text ="Password").place(x=100,y=95)
private_key_password_box = ttk.Entry(tab4, width = 75, textvariable = private_key_password)
private_key_password_box.place(x=300,y=95)
private_key_password_box.config(show="*")
file_to_decrypt_private = ttk.Entry(tab4, width = 75, textvariable = private_key_file_to_decrypt).place(x=300,y=120)
label_file_to_decrypt_private = ttk.Label(tab4, text ="File to Decrypt").place(x=100,y=120)
select_file_to_decrypt_private= ttk.Button(tab4,text="Select File to Decrypt", command=Browse_private_key_file_to_decrypt).place(x=800,y=118)
label_envelope_name_private = ttk.Label(tab4, text ="Envelope").place(x=100,y=145)
envelope_name_private = ttk.Entry(tab4, width=75, textvariable=Private_Envelope_name).place(x=300,y=145)
select_envelope_private= ttk.Button(tab4,text="Select Envelope", command=Browse_envelope).place(x=800,y=142.5)
label_decrypted_file_name_private = ttk.Label(tab4, text ="Enter Desired Decrypted file Name").place(x=100,y=170)
decrypted_file_name_private_box = ttk.Entry(tab4, width=35, textvariable=private_key_decrypted_file_name).place(x=300,y=170)
label_private_key_directory = ttk.Label(tab4, text ="Destination Directory").place(x=100,y=195)
private_key_directory = ttk.Entry(tab4, width = 75, textvariable = private_key_directory_path).place(x=300,y=195)
select_pivate_key_directory = ttk.Button(tab4,text="Select Destination Directory", command=Browse_directory_private_key).place(x=800,y=192.5)
button_private_key_decrypt = ttk.Button(tab4,text="Decrypt", command=Private_key_decrypt).place(x=300,y=225)
show_pass_private = ttk.Checkbutton(tab4,text="Show Password", command=show_priv_fun).place(x=800,y=95)
root.mainloop()  
