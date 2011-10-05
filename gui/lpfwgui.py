import sys, os, thread, time, string, threading
sys.path.append('/sda/workspace/gui/')
from PyQt4.QtGui import QApplication, QStandardItem, QDialog, QIcon, QMenu, QSystemTrayIcon, QStandardItemModel, QAction, QMainWindow
import resource
from PyQt4.QtCore import pyqtSignal
from frontend import Ui_MainWindow
from popupdialog import Ui_Dialog
import IPC_wrapper
from multiprocessing import Pipe, Process

D2FCOMM_ASK = 0
D2FCOMM_LIST = 1
F2DCOMM_LIST = 2
F2DCOMM_ADD = 3
F2DCOMM_DEL = 4
F2DCOMM_DELANDACK = 5
F2DCOMM_WRT = 6
F2DCOMM_REG = 7
F2DCOMM_UNREG = 8

mq_d2fdel=mq_f2d=mq_d2flist=mq_d2f=11
s=p=4
path=pid=0
process_finished = 0

def quitApp():
    print "In quitApp" 
    IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_UNREG)  
    global p
    global process_finished
    process_finished = 1
    p.terminate();
   
    

def listRules():
    IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_LIST)  
    flist = []
    while 1:
        print "mq_d2flist msgrcv start"
        print mq_d2flist, mq_d2f
        item = IPC_wrapper.msgrcv(mq_d2flist)
        print "mq_d2flist msgrcv finished"
        flist.append(item)
        if (item[1] == "EOF"): 
            s.send(flist)  
            print flist
            break


def getFromProcess_thread():
    global s
    global p
    r,s = Pipe()
    p = Process(target=msgq_init_process)
    p.start()
    r.poll(None)
    global mq_d2f
    global mq_d2fdel
    global mq_d2flist
    global mq_f2d
    mq_d2f,mq_d2fdel,mq_d2flist,mq_f2d = r.recv()

    global process_finished
    while 1:
        print "r.poll start"
        while 1:
            print "here %d" %(process_finished)
            if (process_finished):
                break
            try:
                r.poll(None) #returns when there is something to read
                break
                #system may trigger IOError, just retry reading
            except IOError:
                print "IOError caught"
                #this exception may be raised when application is closing and terminates the Process, let's sleep and let app terminate this thread, if we don't then we will be on r.poll and prevent app closing
        
        if (process_finished):
            break
        flist = r.recv()
        print "r.recv finished"
        #check if this is an ASK request
        print len(flist)
        if (flist[0] == D2FCOMM_ASK):
            global path
            global pid
            path = flist[1]
            pid = flist[2]
            
            print "calling emitaskuser"
            window.emitAskUser()
            continue
        
        #if it's not ask request then it is a list request
        #empty the model, we're filling it anew, we can't use clear() cause it flushes headers too, too we do this:
        modelAll.removeRows(0,modelAll.rowCount())
        modelActive.removeRows(0,modelActive.rowCount())
               
        #if there's only one element, it's EOF; dont go through iterations,just leave the model empty
        if (len(flist) == 1): continue
        for item in flist[0:-1]:#leave out the last EOF from iteration
            fullpath = QStandardItem(item[1])
            if (item[2] == "0"):
                pid_string = "N/A"
            else: pid_string = item[2]
            pid = QStandardItem(pid_string)
            perms = QStandardItem(item[3])
            m_list = string.rsplit(item[1],"/",1)
            m_name = m_list[1]
            name = QStandardItem(m_name)
            print "Received: %s" %(item[1])
            if (pid_string != "N/A"):
                fullpath2 = QStandardItem(item[1])
                pid2 = QStandardItem(pid_string)
                perms2 = QStandardItem(item[3])
                name2 = QStandardItem(m_name)
                modelActive.appendRow((name2,pid2,perms2,fullpath2))
                del fullpath2,pid2,perms2,name2
            modelAll.appendRow((name,pid,perms,fullpath))
            #apparently(???) deletion causes its contents to be COPIED into QModel rather than be referenced. If a variable is reused w/out deletion, its contents simply gets re-written
            del fullpath,pid,perms,name
    
    

def msgq_init_process():
    "initializes SysV message queue inter-process communication mechanism, through which frontend will receive instructions from the backend"
      
    FTOKID_D2F = 0
    FTOKID_F2D = 1
    FTOKID_D2FLIST = 2
    FTOKID_F2DLIST = 3
    FTOKID_D2FDEL = 4
    FTOKID_F2DDEL = 5
    FTOKID_CREDS = 6 
    global s,mq_d2f,mq_d2fdel,mq_d2flist,mq_f2d
    
    ftok_d2f = IPC_wrapper.ftok("/tmp/lpfw", FTOKID_D2F)
    mq_d2f= IPC_wrapper.msgget(ftok_d2f, 0)
    ftok_d2flist = IPC_wrapper.ftok("/tmp/lpfw", FTOKID_D2FLIST)
    mq_d2flist= IPC_wrapper.msgget(ftok_d2flist, 0)
    mq_f2d= IPC_wrapper.msgget(IPC_wrapper.ftok("/tmp/lpfw", FTOKID_F2D), 0)
    mq_d2fdel= IPC_wrapper.msgget(IPC_wrapper.ftok("/tmp/lpfw", FTOKID_D2FDEL), 0)
    print "%d %d %d %d" %(mq_d2f,mq_d2fdel,mq_d2flist,mq_f2d)
    
    #send back these IDs - they can't be global vars, cause we are in a different process
    s.send((mq_d2f,mq_d2fdel,mq_d2flist,mq_f2d))
    
    IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_REG)
    listRules()
    
    while 1:
        print "mq_d2 msgrcv start"
        item= IPC_wrapper.msgrcv(mq_d2f)
        print "mq_d2 msgrcv finish"
        if (item[0] == D2FCOMM_ASK):
            print "BE ASKED"
            s.send(item)
            continue
        elif (item[0] == D2FCOMM_LIST):
            print "BE LISTING"
            listRules()
        else:
            print "unknown command"

            
            


class myDialog(QDialog, Ui_Dialog):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.pushButton_allow.clicked.connect(self.allowClicked)
        self.pushButton_deny.clicked.connect(self.denyClicked)
    
    def closeEvent(self, event):
        "in case when user closed the dialog without pressing allow or deny"
        print "in closeEvent"
        IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_ADD, perms = "IGNORED")
            
    def allowClicked(self):
        print "allow clicked"
        if (self.checkBox.isChecked()): verdict = "ALLOW ALWAYS"
        else: verdict = "ALLOW ONCE"
        IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_ADD, perms = verdict)
        listRules()
        
    def denyClicked(self):
        print "deny clicked"
        if (self.checkBox.isChecked()): verdict = "DENY ALWAYS"
        else: verdict = "DENY ONCE"
        IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_ADD, perms = verdict)
        listRules()

class myMainWindow(QMainWindow, Ui_MainWindow):
    askusersig = pyqtSignal()
    quitflag = 0
    
    def saveRules(self):
        IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_WRT)

    
    def showActiveOnly(self):
        self.tableView.setModel(modelActive)
        self.actionShow_active_only.setEnabled(False)
        self.actionShow_all.setEnabled(True)
        self.actionShow_all.setChecked(False)
        
    def showAll(self):
        self.tableView.setModel(modelAll)
        self.actionShow_active_only.setEnabled(True)
        self.actionShow_all.setEnabled(False)
        self.actionShow_active_only.setChecked(False)
        
        

    def askUser(self):
        print "In askUser"
        global path
        global pid
        dialog.label_name.setText(path)
        dialog.label_pid.setText(pid)
        dialog.show()
        
    def rulesMenuTriggered(self):
        "If no rules are selected in the view, grey out the Delete... item"
        if (len(self.tableView.selectedIndexes()) == 0):
            self.menuRules.actions()[0].setEnabled(False)
        else:
            self.menuRules.actions()[0].setEnabled(True)

    def deleteMenuTriggered(self):
        "send delete request to backend"
        index = self.tableView.selectedIndexes()[0]
        #scan model row by row to see which row the item belongs to
        activeModel = self.tableView.model()
        rowCount = activeModel.rowCount()
        colCount = activeModel.columnCount()
        
        i = j = 0
        foundRow = -1
        while (i < rowCount and foundRow == -1) :
            j = 0
            while j < colCount:
                nextindex = activeModel.index(i,j)
                if (index == nextindex):
                    foundRow = i
                    break
                j = j+1
            i = i+1
        
        if (foundRow == -1):
            print "Very strange, item not found. Investigate!!!"
            return
        else:
            mpath = str(activeModel.itemFromIndex(activeModel.index(foundRow,3)).text())
            mpid = str(activeModel.itemFromIndex(activeModel.index(foundRow,1)).text())
            print "start sending item to delete to backend"
            if (mpid == "N/A"): 
                mpid = "0"
            IPC_wrapper.msgsnd(mq_f2d, F2DCOMM_DELANDACK, path=mpath, pid=mpid)
            print "finished sending item to delete to backend"
            #the backend sends an acknowledgement after rule has been deleted, so we could request a fresh dlist
        print "Start waiting for ACK of delete..."
        retval = IPC_wrapper.msgrcv(mq_d2fdel)
        print retval
        print "Received delete ACK"
        #now we need to update the list ourselves
        listRules()
    
    def emitAskUser(self):
        "this is a workaround for not invoking qdialog from a different thread"
        print "in emitAskUser"
        self.askusersig.emit()
         
    def closeEvent(self, event):
        print "in CloseEvent"
        if (self.quitflag == 0):
            event.ignore()
            self.hide()
        else:
            event.accept()
            quitApp()
        
    def realQuit(self):
        self.quitflag = 1
        self.close()
      
    def __init__(self):
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.tableView.setShowGrid(False)
        self.menuRules.aboutToShow.connect(self.rulesMenuTriggered)
        self.menuRules.actions()[0].triggered.connect(self.deleteMenuTriggered)
        self.askusersig.connect(self.askUser)
        self.actionShow_active_only.triggered.connect(self.showActiveOnly)
        self.actionShow_all.triggered.connect(self.showAll)
        self.actionExit.triggered.connect(self.realQuit)
        self.actionSave.triggered.connect(self.saveRules)
        
        #don't clutter console with debuginfo
if (len(sys.argv) <= 1 or sys.argv[1] != "debug"):
    #I don't know how to redirect output to /dev/null so just make a tmp file until I figure out
    logfile = open("/tmp/lpfwguipy.log", "w")
    sys.stdout = logfile
        
app=QApplication(sys.argv)
app.setQuitOnLastWindowClosed(True)
window = myMainWindow()
icon = QIcon(":/pics/pic.jpg")
window.setWindowIcon(icon)
window.setWindowTitle("Leopard Flower firewall")
window.show()

tray = QSystemTrayIcon(icon)
menu = QMenu()
actionShow = QAction("Show Leopard Flower",menu)
actionExit = QAction("Exit",menu)
menu.addAction(actionShow)
menu.addAction(actionExit)
tray.setContextMenu(menu)
tray.show()
actionShow.triggered.connect(window.show)
actionExit.triggered.connect(window.realQuit)


modelAll = QStandardItemModel()
modelAll.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path"))
modelActive = QStandardItemModel()
modelActive.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path"))
window.tableView.setModel(modelAll)
dialog = myDialog()
dialog.setWindowTitle("Leopard Flower firewall")

#start the thread which initializes msgq and listens for be requests
#thread.start_new_thread(getFromProcess_thread, ())

m_thread = threading.Thread(target=getFromProcess_thread)
m_thread.daemon = False
m_thread.start()

sys.exit(app.exec_())
