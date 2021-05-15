from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
from tkinter import *
from encryption import *
from auxFunctions import *

#!!!!: Make error window
def error(msg):
    messagebox.showerror("Error", msg)

def browse_button():
    # Allow user to select a directory and store it in global var
    # called folder_path
    global folder_path
    if(i.get()==1):
        filename = filedialog.askdirectory()
    else:
        filename = filedialog.askopenfilename()
    folder_path.set(filename)

#Encrypt or decrypt opens a new window to get password
def EncryptFolder():
    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        openPassWindow()
        encryptFolder(folder_path.get())
        folder_path.set("")
        pswd = ""
    return

def DecryptFolder():
    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        openPassWindow()
        decryptFolder(folder_path.get())
        folder_path.set("")
        pswd = ""
    return

def EncryptFile():

    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        openPassWindow()
        encryptFile(folder_path.get())
        folder_path.set("")
        pswd = ""

    return

def DecryptFile():

    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        openPassWindow()
        decryptFile(folder_path.get())
        folder_path.set("")
        pswd = ""

    return

def EncryptAction():

    if i.get() == 1:
        EncryptFolder()
    else:
        EncryptFile()

    return

def DecryptAction():

    if i.get() == 1:
        DecryptFolder()
    else:
        DecryptFile()

    return

pswd = ""

#bool shown is used for password visibility 
shown=False
def openPassWindow(): 
    global pswd
    pass_ = StringVar()
    pass_.set("")

    pass_conf = StringVar()
    pass_conf.set("")

    
    #function when confirm password button is clicked, which destroys the password window
    def encryptionAction():#!!!!: make pass confirmation 
        global pswd
        if pass_.get() == pass_conf.get():
            pswd = pass_.get()
            pass_.set("")
            newWindow.destroy()
        else:
            error("Password mismatch")

        
        

    #function for displaying or hiding password
    def show():
        global shown
        if(shown == False ):
            pass_box.config(show="")
            conf_pass_box.config(show="")
            shown = True
        else:
            pass_box.config(show="*")
            conf_pass_box.config(show="*")
            shown = False
    
    #creating a new window
    root1 = Tk()
    newWindow = root1
    newWindow.grab_set()
    newWindow.title("Password Entry") 
    newWindow.geometry("500x300") 
    newWindow.resizable(width=False, height=False)

    #first label and textbox for password
    label = ttk.Label(newWindow, text ="Enter Password").place(x=20,y=40)
    pass_box = ttk.Entry(newWindow, width=35, textvariable = pass_)
    pass_box.place(x=130,y=40)
    pass_box.config(show="*")

    #second label and textbox for password confirmation
    label = ttk.Label(newWindow, text ="Confirm Password").place(x=20,y=75)
    conf_pass_box = ttk.Entry(newWindow, width=35, textvariable=pass_conf)
    conf_pass_box.place(x=130,y=75)
    conf_pass_box.config(show="*")

    #show_pass checkbutton shows password, conf_pass button confirms password entries and destroys the window
    show_pass = ttk.Checkbutton(newWindow,text="Show Password", command=show).place(x=350,y=75)
    conf_pass = ttk.Button(newWindow,text="Confirm", command=encryptionAction).place(x=180,y=110)

    return root1

if __name__ == "__main__":

    if is_admin():

        #Creating main window
        root = Tk()
        root.title("Security")
        root.geometry('1100x700')
        root.resizable(width=False, height=False)
        folder_path = StringVar()
        folder_path.set("")

        #!!!!: Make Compatible for Files. Use Radios for options

        #Textbox and button to insert filepath
        folderBox = ttk.Entry(root, width = 75, textvariable = folder_path).place(x=300,y=70)
        button_browse = ttk.Button(text="Browse", command=browse_button).place(x=800,y=68)

        #Radio buttons for folders and files

        i = IntVar() 
        i.set(1)
        r1 = ttk.Radiobutton(root, text="Folders", value=1, variable=i).place(x=300,y=100)
        r2 = ttk.Radiobutton(root, text="Files", value=2, variable=i).place(x=400,y=100)


        #Encryption and Decryption buttons
        button_encrypt = ttk.Button(text="Encrypt", command=EncryptAction).place(x=370,y=135)

        button_decrypt = ttk.Button(text="Decrypt", command=DecryptAction).place(x=650,y=135)

        mainloop()

    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)