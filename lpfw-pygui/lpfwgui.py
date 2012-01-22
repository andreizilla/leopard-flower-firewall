import sys, os, thread, time, string, threading, subprocess
from PyQt4.QtGui import QApplication, QStandardItem, QDialog, QIcon, QMenu, QSystemTrayIcon, QStandardItemModel, QAction, QMainWindow, QListWidget, QListWidgetItem, QWidget, QIntValidator
import resource
from PyQt4.QtCore import pyqtSignal, Qt
from frontend import Ui_MainWindow
from popup_out import Ui_DialogOut
from popup_in import Ui_DialogIn
from prefs import Ui_Form
from multiprocessing import Pipe, Process, Lock

D2FCOMM_ASK_OUT = 0
D2FCOMM_ASK_IN = 1
D2FCOMM_LIST = 2
F2DCOMM_LIST = 3
F2DCOMM_ADD = 4
F2DCOMM_DEL = 5
F2DCOMM_DELANDACK = 6
F2DCOMM_WRT = 7
F2DCOMM_REG = 8
F2DCOMM_UNREG = 9

#global vars
proc = 0
path=pid=perms=0
ruleslock = 0

def send_to_backend(message):
    global proc
    proc.stdin.write(message)
    #sleep is required to achieve unbufferedness, otherwise messages get buffered sometimes
    time.sleep(0.1)


def refreshmodel(ruleslist):  
    "Fill the frontend with rules data"
    #empty the model, we're filling it anew, we can't use clear() cause it flushes headers too:
    global ruleslock
    ruleslock.acquire()
    #modelAll contains all rules, modelActive - only those which are currently running and have transfered at least some traffic
    modelAll.removeRows(0,modelAll.rowCount())
    modelActive.removeRows(0,modelActive.rowCount())
           
    #if there's only one element, it's EOF; dont go through iterations,just leave the model empty
    if (len(ruleslist) == 1):
        ruleslock.release()
        return
    for item in ruleslist[0:-1]:#leave out the last EOF from iteration
        if (item[0] == "KERNEL_PROCESS"):
            #a whole different ball game starts with KERNEL_PROCESS
            ker_name = QStandardItem("KERNEL")
            ker_pid = QStandardItem("N/A")
            ker_perms = QStandardItem("ALLOW_ALWAYS")
            ker_fullpath = QStandardItem("KERNEL-> "+item[1])
            ker_in_traf = QStandardItem()
            ker_out_traf = QStandardItem()
            modelAll.appendRow((ker_name,ker_pid,ker_perms,ker_fullpath,ker_in_traf,ker_out_traf))
            #see below why del is needed
            del ker_fullpath,ker_pid,ker_perms,ker_name,ker_in_traf,ker_out_traf
        else:
            fullpath = QStandardItem(item[0])
            #item[4] contains nfmark
            fullpath.setData(item[4])
            if (item[1] == "0"):
                pid_string = "N/A"
            else: 
                pid_string = item[1]
            pid = QStandardItem(pid_string)
            perms = QStandardItem(item[2])
            #only the name of the executable after the last /
            m_list = string.rsplit(item[0],"/",1)
            m_name = m_list[1]
            name = QStandardItem(m_name)
            in_traf = QStandardItem()
            out_traf = QStandardItem()
            modelAll.appendRow((name,pid,perms,fullpath,in_traf,out_traf))
            del fullpath,pid,perms,name,in_traf,out_traf
            print "Received: %s" %(item[0])
            if (pid_string != "N/A"):
                fullpath2 = QStandardItem(item[0])
                fullpath2.setData(item[4])
                pid2 = QStandardItem(pid_string)
                perms2 = QStandardItem(item[2])
                name2 = QStandardItem(m_name)
                in_traf2 = QStandardItem()
                out_traf2 = QStandardItem()
                modelActive.appendRow((name2,pid2,perms2,fullpath2,in_traf2,out_traf2))
                del fullpath2,pid2,perms2,name2, in_traf2, out_traf2
#apparently(???) deletion causes its contents to be COPIED into QModel rather than be referenced. If a variable is reused w/out deletion, its contents simply gets re-written
    ruleslock.release()
    
    
def quitApp():
    print "In quitApp" 
    send_to_backend("F2DCOMM_UNREG")
    send_to_backend("QUIT")

   
def traffic_handler(ruleslist):
    "Receive every second nfmarks and traffic stats and put them in the model"
    global ruleslock
    ruleslock.acquire()
    #take all nfmarks 0th 3rd 6th etc. and look them up in the model
    i = -1
    for nfmark in ruleslist:
        i = i + 1
        if ((i % 3) != 0): #only every third
            continue
        for j in range(modelAll.rowCount()):
            #4th element of each line has nfmark in its data field
            if (modelAll.item(j,3).data().toString() == nfmark):
                modelAll.item(j,4).setText(str(ruleslist[i+1]))
                modelAll.item(j,5).setText(str(ruleslist[i+2]))
        for j in range(modelActive.rowCount()):
            #4th element of each line has nfmark in its data field
            if (modelActive.item(j,3).data().toString() == nfmark):
                modelActive.item(j,4).setText(str(ruleslist[i+1]))
                modelActive.item(j,5).setText(str(ruleslist[i+2]))
        
    ruleslock.release()
    
    
def stdoutthread(stdout):
    "receive commands from backend"
    global path
    global pid
    global perms
    while 1:
        message = stdout.readline() #readline needs \n to unblock, it doesnt clear that \n though        
        msglist = []
        msglist = message.split(' ')    
        if msglist[0] == "RULESLIST":
            #rules in format (path, pid, perms, isactive, nfmark) with trailing EOF
            print msglist
            ruleslist = []
            item = []
            i = 0
            while (msglist[i*5+1] != "EOF\n"):
                item.append(msglist[5*i+1])
                item.append(msglist[5*i+2])
                item.append(msglist[5*i+3])
                item.append(msglist[5*i+4])
                item.append(msglist[5*i+5])            
                ruleslist.append(item)
                item = []
                i = i+1
            ruleslist.append("EOF")
            print ruleslist
            refreshmodel(ruleslist)
            continue
        elif msglist[0] == "TRAFFIC":
            msglist.pop(0)
            traffic_handler(msglist)
        elif msglist[0] == "D2FCOMM_LIST":
            send_to_backend("F2DCOMM_LIST")
        elif msglist[0] == "D2FCOMM_ASK_OUT":
            path = msglist[1]
            pid = msglist[2]
            print "calling emitaskuserOUT"
            window.emitAskUserOUT()
        elif msglist[0] == "D2FCOMM_ASK_IN":
            path = msglist[1]
            pid = msglist[2]
            perms = msglist[3]
            print "calling emitaskuserIN"
            window.emitAskUserIN()            
            
                   
def msgq_init(): 
    print "in msgq_init"
    global proc
    proc = subprocess.Popen(["./ipc_wrapper2"], shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
     
    stdout_thread = threading.Thread(target=stdoutthread, args=(proc.stderr,))
    #daemonize the thread, meaning it will exit when main() exits. This is needed b/c the thread will be blocking on reeading pipe
    stdout_thread.daemon = True
    stdout_thread.start()
    
    send_to_backend("F2DCOMM_REG ")
    send_to_backend("F2DCOMM_LIST ")

    
class myDialogOut(QDialog, Ui_DialogOut):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.pushButton_allow.clicked.connect(self.allowClicked)
        self.pushButton_deny.clicked.connect(self.denyClicked)
        self.rejected.connect(self.escapePressed)
        
    def escapePressed(self):
        "in case when user pressed Escape"
        print "in escapePressed"
        send_to_backend("F2DCOMM_ADD IGNORED")
     
    def closeEvent(self, event):
        "in case when user closed the dialog without pressing allow or deny"
        print "in closeEvent"
        send_to_backend("F2DCOMM_ADD IGNORED")
            
    def allowClicked(self):
        print "allow clicked"
        if (self.checkBox.isChecked()): verdict = "ALLOW_ALWAYS"
        else: verdict = "ALLOW_ONCE"     
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")
        
    def denyClicked(self):
        print "deny clicked"
        if (self.checkBox.isChecked()): verdict = "DENY_ALWAYS"
        else: verdict = "DENY_ONCE"     
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")
             
        
class myDialogIn(QDialog, Ui_DialogIn):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.pushButton_allow.clicked.connect(self.allowClicked)
        self.pushButton_deny.clicked.connect(self.denyClicked)
        self.rejected.connect(self.escapePressed) #when Esc is pressed
        
    def escapePressed(self):
        "in case when user pressed Escape"
        print "in escapePressed"
        send_to_backend("F2DCOMM_ADD IGNORED")
         
    def closeEvent(self, event):
        "in case when user closed the dialog without pressing allow or deny"
        print "in closeEvent"
        send_to_backend("F2DCOMM_ADD IGNORED")
            
    def allowClicked(self):
        print "allow clicked"
        if (self.checkBox.isChecked()): verdict = "ALLOW_ALWAYS"
        else: verdict = "ALLOW_ONCE"   
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")

        
    def denyClicked(self):
        print "deny clicked"
        if (self.checkBox.isChecked()): verdict = "DENY_ALWAYS"
        else: verdict = "DENY_ONCE"
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")
        
        
class mForm(QWidget, Ui_Form):
    def __init__(self):
        QWidget.__init__(self)
        self.setupUi(self)
        self.pushButton_Add.clicked.connect(self.addIP)
        validator = QIntValidator()
        validator.setRange(0,255)
        self.lineEdit_IP_1.setValidator(validator)
        self.lineEdit_IP_2.setValidator(validator)
        self.lineEdit_IP_3.setValidator(validator)
        self.lineEdit_IP_4.setValidator(validator)

        
    def addIP(self):
        ip1 = str(self.lineEdit_IP_1.text())
        ip2 = str(self.lineEdit_IP_2.text())
        ip3 = str(self.lineEdit_IP_3.text())
        ip4 = str(self.lineEdit_IP_4.text())
        
        if (ip1 == ""):
            self.lineEdit_IP_1.setFocus()
            return
        elif (ip2 == ""):
            self.lineEdit_IP_2.setFocus()
            return
        elif (ip3 == ""):
            self.lineEdit_IP_3.setFocus()
            return
        elif (ip4 == ""): 
            self.lineEdit_IP_4.setFocus()
            return
        ip = ip1+"."+ip2+"."+ip3+"."+ip4
        
        self.hide()
        send_to_backend("F2DCOMM_ADD KERNEL_PROCESS %s ALLOW_ALWAYS " %(ip))
        send_to_backend("F2DCOMM_LIST")        
        
        
        
class myMainWindow(QMainWindow, Ui_MainWindow):
    askuserINsig = pyqtSignal() #connected to askUserIN
    askuserOUTsig = pyqtSignal() #connected to askUserOUT
    quitflag = 0
    
    def saveRules(self):
        send_to_backend("F2DCOMM_WRT")       
    
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
    
    def askUserOUT(self):
        print "In askUserOut"
        global path
        global pid
        dialogOut.label_name.setText(path)
        dialogOut.label_pid.setText(pid)
        dialogOut.show()
        
    def askUserIN(self):
        print "In askUserIn"
        global path
        global pid
        global perms
        dialogIn.label_name.setText(path)
        dialogIn.label_pid.setText(pid)
        dialogIn.label_ip.setText(str(perms))
        dialogIn.show()
        
    def rulesMenuTriggered(self):
        "If no rules are selected in the view, grey out the Delete... item"
        if (len(self.tableView.selectedIndexes()) == 0):
            self.menuRules.actions()[0].setEnabled(False)
        else:
            self.menuRules.actions()[0].setEnabled(True)

    def deleteMenuTriggered(self):
        "send delete request to backend"
        if (len(self.tableView.selectedIndexes()) == 0):
            #after rulesmenu was triggered, the model refreshed and no index is selected anymore
            return
        index = self.tableView.selectedIndexes()[0]
        #scan model row by row to see which row the selected item belongs to
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
                if (mpath.find("KERNEL-> ") == 0):
                    mpid = mpath.lstrip("KERNEL-> ") #IP goes to pid field
                    mpath = "KERNEL_PROCESS"
                else:    
                    mpid = "0"
            
            send_to_backend("F2DCOMM_DELANDACK %s %s " %(mpath,mpid))
               
    def emitAskUserOUT(self):
        "this is a workaround for not invoking qdialog from a different thread"
        print "in emitAskUserOut"
        self.askuserOUTsig.emit()
        
    def emitAskUserIN(self):
        "this is a workaround for not invoking qdialog from a different thread"
        print "in emitAskUserIn"
        self.askuserINsig.emit()
         
    def closeEvent(self, event):
        print "in CloseEvent"
        if (self.quitflag == 0):
            event.ignore()
            self.hide()
        else:
            event.accept()
            quitApp()
        
    def realQuit(self): 
        print "in realQuit"
        self.quitflag = 1
        self.close()

    def showPrefs(self):
        prefs_dialog.show()
        
    def __init__(self):
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.tableView.setShowGrid(False)
        self.menuRules.aboutToShow.connect(self.rulesMenuTriggered)
        self.menuRules.actions()[0].triggered.connect(self.deleteMenuTriggered)
        self.askuserOUTsig.connect(self.askUserOUT)
        self.askuserINsig.connect(self.askUserIN)
        self.actionShow_active_only.triggered.connect(self.showActiveOnly)
        self.actionShow_all.triggered.connect(self.showAll)
        self.actionPreferences_2.triggered.connect(self.showPrefs)
        self.actionExit.triggered.connect(self.realQuit)
        self.actionSave.triggered.connect(self.saveRules)
        
    #don't clutter console with debuginfo
if (len(sys.argv) <= 1 or sys.argv[1] != "debug"):
    #I don't know how to redirect output to /dev/null so just make a tmp file until I figure out
    logfile = open("/dev/null", "w")
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
modelAll.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path", "Incoming allowed", "Outgoing allowed"))
modelActive = QStandardItemModel()
modelActive.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path", "Incoming allowed", "Outgoing allowed"))
window.tableView.setModel(modelAll)
dialogOut = myDialogOut()
dialogOut.setWindowTitle("Leopard Flower firewall")
dialogIn = myDialogIn()
dialogIn.setWindowTitle("Leopard Flower firewall")
prefs_dialog = mForm()

ruleslock = Lock();
msgq_init()
sys.exit(app.exec_())
