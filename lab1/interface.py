import tkinter
from protodaemon import kill_daemon,create_daemon
def stop():
    print('Daemon is complete')
    kill_daemon()
    
        
        

def startclick():
    print('Daemon is starting')
    create_daemon()


def restart():
    stop_daemon()
    startclick()


window = tkinter.Tk()
window.geometry('500x550')

lb1 = tkinter.Label(window, text='Choose mode', font='Cascadia')
lb1.place(relx=0.5, rely=0.1, anchor='center')

but1 = tkinter.Button(window, text='Start', font='Cascadia', command=startclick)
but1.place(relx=0.5, rely=0.2, width=150, anchor='center')

but2 = tkinter.Button(window, text='Restart', font='Cascadia', command=restart)
but2.place(relx=0.5, rely=0.3, width=150, anchor='center')

but3 = tkinter.Button(window, text='Stop', font='Cascadia', command=stop)
but3.place(relx=0.5, rely=0.4, width=150, anchor='center')

window.mainloop()
