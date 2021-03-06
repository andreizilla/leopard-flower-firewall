import sys, os, thread, time, string, threading, subprocess
from PyQt4.QtGui import QApplication, QStandardItem, QDialog, QIcon, QMenu, QSystemTrayIcon, QStandardItemModel, QAction, QMainWindow, QListWidget, QListWidgetItem, QWidget, QIntValidator, QStyledItemDelegate, QPainter, QStyleOptionViewItem, QFont, QTableWidgetItem
import resource
from PyQt4.QtCore import pyqtSignal, Qt, QModelIndex, QRect
from PyQt4.QtNetwork import QHostInfo
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
path=pid=addr=sport=dport=0
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
            ker_in_allow_traf = QStandardItem()
            ker_out_allow_traf = QStandardItem()
            ker_in_deny_traf = QStandardItem()
            ker_out_deny_traf = QStandardItem()
            modelAll.appendRow((ker_name,ker_pid,ker_perms,ker_fullpath,ker_in_allow_traf,ker_out_allow_traf,ker_in_deny_traf,ker_out_deny_traf))
            #see below why del is needed
            del ker_fullpath,ker_pid,ker_perms,ker_name,ker_in_allow_traf,ker_out_allow_traf,ker_in_deny_traf,ker_out_allow_traf
        else:
            fullpath = QStandardItem(unicode(item[0], "utf-8"))
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
            name = QStandardItem(unicode(m_name, "utf-8"))
            in_allow_traf = QStandardItem()
            out_allow_traf = QStandardItem()
            in_deny_traf = QStandardItem()
            out_deny_traf = QStandardItem()
            modelAll.appendRow((name,pid,perms,fullpath,in_allow_traf,out_allow_traf,in_deny_traf,out_deny_traf))
            del fullpath,pid,perms,name,in_allow_traf,out_allow_traf,in_deny_traf,out_deny_traf
            print "Received: %s" %(item[0])
            if (pid_string != "N/A"):
                fullpath2 = QStandardItem(unicode (item[0], "utf-8"))
                fullpath2.setData(item[4])
                pid2 = QStandardItem(pid_string)
                perms2 = QStandardItem(item[2])
                name2 = QStandardItem(unicode(m_name, "utf-8"))
                in_allow_traf2 = QStandardItem()
                out_allow_traf2 = QStandardItem()
                in_deny_traf2 = QStandardItem()
                out_deny_traf2 = QStandardItem()
                modelActive.appendRow((name2,pid2,perms2,fullpath2,in_allow_traf2,out_allow_traf2,in_deny_traf2,out_deny_traf2))
                del fullpath2,pid2,perms2,name2,in_allow_traf2,out_allow_traf2,in_deny_traf2,out_deny_traf2
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
    #take all nfmarks 0th 5th 10th etc. and look them up in the model
    i = -1
    for nfmark in ruleslist:
        i = i + 1
        if ((i % 5) != 0): #only every 5th
            continue
        for j in range(modelAll.rowCount()):
            #4th element of each line has nfmark in its data field
            if (modelAll.item(j,3).data().toString() == nfmark):
                modelAll.item(j,4).setText(str(ruleslist[i+1]))
                modelAll.item(j,5).setText(str(ruleslist[i+2]))
                modelAll.item(j,6).setText(str(ruleslist[i+3]))
                modelAll.item(j,7).setText(str(ruleslist[i+4]))

        for j in range(modelActive.rowCount()):
            #4th element of each line has nfmark in its data field
            if (modelActive.item(j,3).data().toString() == nfmark):
                modelActive.item(j,4).setText(str(ruleslist[i+1]))
                modelActive.item(j,5).setText(str(ruleslist[i+2]))
                modelActive.item(j,6).setText(str(ruleslist[i+3]))
                modelActive.item(j,7).setText(str(ruleslist[i+4]))
        
    ruleslock.release()
    
    
def stdoutthread(stdout):
    "receive commands from backend"
    global path
    global pid
    global addr
    global sport
    global dport
    while 1:
        message = stdout.readline() #readline needs \n to unblock, it doesnt clear that \n though        
        msglist = []
        msglist = message.split('\a')    
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
            addr = msglist[3]
            sport = msglist[4]
            dport = msglist[5]
            print "calling emitaskuserOUT"
            window.emitAskUserOUT()
        elif msglist[0] == "D2FCOMM_ASK_IN":
            path = msglist[1]
            pid = msglist[2]
            addr = msglist[3]
            sport = msglist[4]
            dport = msglist[5]
            print "calling emitaskuserIN"
            window.emitAskUserIN()            


def msgq_init(): 
    print "in msgq_init"
    global proc
    proc = subprocess.Popen(["./lpfw-pygui/ipc_wrapper2"], shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
     
    stdout_thread = threading.Thread(target=stdoutthread, args=(proc.stderr,))
    #daemonize the thread, meaning it will exit when main() exits. This is needed b/c the thread will be blocking on reading pipe
    stdout_thread.daemon = True
    stdout_thread.start()
        
    send_to_backend("F2DCOMM_REG ")
    send_to_backend("F2DCOMM_LIST ")

    
class myDialogOut(QDialog, Ui_DialogOut):
    dns_lookup_id = 0
    host = 0
    def __init__(self):
        self.dns_lookup_id = 0  
        QDialog.__init__(self)
        self.setupUi(self)
        self.pushButton_allow.clicked.connect(self.allowClicked)
        self.pushButton_deny.clicked.connect(self.denyClicked)
        self.pushButton_hide.setVisible(False)
        self.tableWidget_details.setVisible(False)
        self.rejected.connect(self.escapePressed)
        self.finished.connect(self.dialogFinished)

        fullpath_text = QTableWidgetItem("Full path")
        self.tableWidget_details.setItem(0,0,fullpath_text)
        pid_text = QTableWidgetItem("Process ID")
        self.tableWidget_details.setItem(1,0,pid_text)
        remoteip_text = QTableWidgetItem("Remote IP")
        self.tableWidget_details.setItem(2,0,remoteip_text)
        remotedomain_text = QTableWidgetItem("Remote domain")
        self.tableWidget_details.setItem(3,0,remotedomain_text)
        remoteport_text = QTableWidgetItem("Remote port")
        self.tableWidget_details.setItem(4,0,remoteport_text)
        localport_text = QTableWidgetItem("Local port")
        self.tableWidget_details.setItem(5,0,localport_text)
        
        
    def escapePressed(self):
        "in case when user pressed Escape"
        print "in escapePressed"
        self.done(1)
        send_to_backend("F2DCOMM_ADD IGNORED")
     
    def closeEvent(self, event):
        "in case when user closed the dialog without pressing allow or deny"
        print "in closeEvent"
        self.done(2)        
        send_to_backend("F2DCOMM_ADD IGNORED")
            
    def allowClicked(self):
        print "allow clicked"
        self.done(3)        
        if (self.checkBox.isChecked()): verdict = "ALLOW_ALWAYS"
        else: verdict = "ALLOW_ONCE"     
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")
        
    def denyClicked(self):
        print "deny clicked"
        self.done(4)
        if (self.checkBox.isChecked()): verdict = "DENY_ALWAYS"
        else: verdict = "DENY_ONCE"     
        send_to_backend("F2DCOMM_ADD %s " %(verdict))
        send_to_backend("F2DCOMM_LIST")
             
    def dialogFinished(self):
         QHostInfo.abortHostLookup(self.dns_lookup_id)
         
    def dnsLookupFinished(self, host):
        if ( host.error() != QHostInfo.NoError):
            print "Lookup failed %s" %(host.errorString())
            return
        hostname = host.hostName()
        item = QTableWidgetItem(hostname)
        self.tableWidget_details.setItem(3,1,item)
        self.label_domain.setText(hostname)

        
        
        
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
        global addr
        global sport
        global dport
        name = string.rsplit(path,"/",1)
        dialogOut.label_name.setText(unicode(name[1], "utf-8"))
        dialogOut.label_ip.setText(addr)
        dialogOut.label_domain.setText("Looking up DNS...")
        fullpath = QTableWidgetItem(unicode(path, "utf-8"))
        dialogOut.tableWidget_details.setItem(0,1,fullpath)
        pid_item = QTableWidgetItem(pid)
        dialogOut.tableWidget_details.setItem(1,1,pid_item)
        remoteip = QTableWidgetItem(addr)
        dialogOut.tableWidget_details.setItem(2,1,remoteip)
        dns = QTableWidgetItem("Looking up DNS...")
        dialogOut.tableWidget_details.setItem(3,1,dns)
        dport_item = QTableWidgetItem(dport)
        dialogOut.tableWidget_details.setItem(4,1,dport_item)
        sport_item = QTableWidgetItem(sport)
        dialogOut.tableWidget_details.setItem(5,1,sport_item)
        QHostInfo.lookupHost(addr, dialogOut.dnsLookupFinished)
        #we don't want the user to accidentally click ALLOW
        
        dialogOut.show()

        
    def askUserIN(self):
        print "In askUserIn"
        global path
        global addr
        global dport
        dialogIn.label_name.setText(unicode(path, "utf-8"))
        dialogIn.label_port.setText(dport)
        dialogIn.label_ip.setText(str(addr))
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
   
class CustomDelegate (QStyledItemDelegate):
    def __init__ (self):
        QStyledItemDelegate.__init__(self)
    def paint (self, painter, option, index):
        model = index.model()
        item = QStandardItem()
        item = model.item(index.row(), index.column())
        text = item.text()
        if (len(text) > 6):
            # take only megabytes -->12<--345678
            mb = text[:len(text)-6]
            bytes = text[len(text)-6:]
            painter.setPen (Qt.red)
            painter.drawText (option.rect,Qt.AlignHCenter and Qt.AlignVCenter, mb)
            painter.setPen (Qt.black)
            rect = QRect()
            rect = option.rect
            rect.setX(rect.x()+8*(len(mb)))  
            painter.drawText (rect, Qt.AlignHCenter and Qt.AlignVCenter, bytes)
        else:
            # painter.setPen (Qt.black)
            #font = QFont("Arial",15)
            #painter.setFont(font)
            painter.drawText (option.rect, Qt.AlignHCenter and Qt.AlignVCenter, text)
        
            
            
        
        
                      
        
    #don't clutter console with debuginfo
if (len(sys.argv) <= 1 or sys.argv[1] != "debug"):
    #I don't know how to redirect output to /dev/null so just make a tmp file until I figure out
    logfile = open("/dev/null", "w")
    sys.stdout = logfile
elif (sys.argv[1] == "debug"):
    import wingdbstub  
    
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

delegate = CustomDelegate()

modelAll = QStandardItemModel()
modelAll.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path","Incoming allowed","Outgoing allowed","Incoming denied","Outgoing denied"))
modelActive = QStandardItemModel()
modelActive.setHorizontalHeaderLabels(("Name","Process ID","Permissions","Full path","Incoming allowed","Outgoing allowed","Incoming denied","Outgoing denied"))
window.tableView.setModel(modelAll)
window.tableView.setItemDelegateForColumn(4,delegate)
window.tableView.setItemDelegateForColumn(5,delegate)
window.tableView.setItemDelegateForColumn(6,delegate)
window.tableView.setItemDelegateForColumn(7,delegate)

dialogOut = myDialogOut()
dialogOut.setWindowTitle("Leopard Flower firewall")
dialogIn = myDialogIn()
dialogIn.setWindowTitle("Leopard Flower firewall")
prefs_dialog = mForm()

ruleslock = Lock();
msgq_init()
sys.exit(app.exec_())
