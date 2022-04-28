from tkinter import *
import localcheck

class Window(Frame):

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master

        # widget can take all window
        self.pack(fill=BOTH, expand=1)

        localCheckButton = Button(self, text="check local certificates", command=self.clickLocalCheckButton)
        localCheckButton.place(x=0, y=0)

    def clickExitButton(self):
        exit()

    def clickLocalCheckButton(self):

        localcheck.localcheck()
        print("test 2")

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

