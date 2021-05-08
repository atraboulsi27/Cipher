#!!!!: Use ttk 
#!!!!: Make Compatible for Files. Use Radios for options
#!!!!: Make error window
#!!!!: make pass confirmation 

from tkinter import filedialog
from tkinter import *
from encryption import *
from auxFunctions import *

#!!!!: Make error window
def error(msg):
    print(msg)

def browse_button():
    # Allow user to select a directory and store it in global var
    # called folder_path
    global folder_path
    filename = filedialog.askdirectory()
    folder_path.set(filename)

#Encrypt or decrypt opens a new window to get password
def encryptFolder():
    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        encryptFolder(folder_path.get())
        folder_path.set("")
    
    return

def decryptFolder():
    if folder_path.get() == "" :
        error("No folder selected !")
    else:
        decryptFolder(folder_path.get())
        folder_path.set("")
    return

def encryptFile():
    return

def decryptFile():
    return

#bool shown is used for password visibility 
shown=False
def openPassWindow(): 

    global pass_
    pass_conf = StringVar()
    pass_conf.set("")

    #function when confirm password button is clicked, which destroys the password window
    def encryptionAction():#!!!!: make pass confirmation 
        if pass_.get() == conf_pass_box:
            newWindow.destroy()
        

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
    newWindow = Toplevel(root) 
    newWindow.grab_set()
    newWindow.title("Password Entry") 
    newWindow.geometry("500x300") 
    newWindow.resizable(width=False, height=False)

    #first label and textbox for password
    label = Label(newWindow, text ="Enter Password").place(x=20,y=40)
    pass_box = Entry(newWindow, width=35, textvariable = pass_)
    pass_box.place(x=130,y=40)
    pass_box.config(show="*")

    #second label and textbox for password confirmation
    label = Label(newWindow, text ="Confirm Password").place(x=20,y=75)
    conf_pass_box = Entry(newWindow, width=35)
    conf_pass_box.place(x=130,y=75)
    conf_pass_box.config(show="*")

    #show_pass checkbutton shows password, conf_pass button confirms password entries and destroys the window
    show_pass = Checkbutton(newWindow,text="Show Password", command=show).place(x=350,y=75)
    conf_pass = Button(newWindow,text="Confirm", command=encryptionAction).place(x=180,y=110)

    return 


if is_admin():
    
    #Creating main window
    root = Tk()
    root.title("Security")
    root.geometry('1100x700')
    root.resizable(width=False, height=False)
    folder_path = StringVar()
    folder_path.set("")
    pass_ = StringVar()
    pass_.set("")

    #!!!!: Make Compatible for Files. Use Radios for options

    #Textbox and button to insert filepath
    folderBox = Entry(root, width = 75, textvariable = folder_path).place(x=300,y=70)
    button_browse = Button(text="Browse", command=browse_button).place(x=800,y=68)

    #Encryption and Decryption buttons
    button_encrypt = Button(text="Encrypt", command=encryptFolder).place(x=370,y=120)

    button_decrypt = Button(text="Decrypt", command=decryptFolder).place(x=650,y=120)

    mainloop()

else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

