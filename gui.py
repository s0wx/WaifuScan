#! /usr/bin/python3
from tkinter import Frame, BOTH, Button, Tk

from lib.localcheck import localcheck


class Window(Frame):

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master

        # widget can take all window
        self.pack(fill=BOTH, expand=1)

        localCheckButton = Button(self, text="check local certificates", bg="green", command=self.clickLocalCheckButton)
        localCheckButton.place(x=0, y=0)

    def clickExitButton(self):
        exit()

    def clickLocalCheckButton(self):
        localcheck()

    # def clickMonitorNetworkCerts(self):
    # return


if __name__ == '__main__':
    root = Tk()
    app = Window(root)
    root.wm_title("CertFinder+")
    root.geometry("500x500")
    root.mainloop()

'''class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master


if __name__ == '__main__':

    root = Tk()
    app = Window(root)
    root.wm_title("Certfinder+")
    root.mainloop()'''
