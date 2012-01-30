# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'prefs.ui'
#
# Created: Thu Feb  2 22:28:41 2012
#      by: PyQt4 UI code generator 4.7.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(370, 170)
        self.groupBox_2 = QtGui.QGroupBox(Form)
        self.groupBox_2.setGeometry(QtCore.QRect(10, 0, 351, 161))
        self.groupBox_2.setObjectName("groupBox_2")
        self.lineEdit_IP_1 = QtGui.QLineEdit(self.groupBox_2)
        self.lineEdit_IP_1.setGeometry(QtCore.QRect(20, 70, 31, 21))
        self.lineEdit_IP_1.setText("")
        self.lineEdit_IP_1.setObjectName("lineEdit_IP_1")
        self.lineEdit_IP_2 = QtGui.QLineEdit(self.groupBox_2)
        self.lineEdit_IP_2.setGeometry(QtCore.QRect(60, 70, 31, 21))
        self.lineEdit_IP_2.setText("")
        self.lineEdit_IP_2.setObjectName("lineEdit_IP_2")
        self.lineEdit_IP_3 = QtGui.QLineEdit(self.groupBox_2)
        self.lineEdit_IP_3.setGeometry(QtCore.QRect(100, 70, 31, 21))
        self.lineEdit_IP_3.setText("")
        self.lineEdit_IP_3.setObjectName("lineEdit_IP_3")
        self.lineEdit_IP_4 = QtGui.QLineEdit(self.groupBox_2)
        self.lineEdit_IP_4.setGeometry(QtCore.QRect(140, 70, 30, 21))
        self.lineEdit_IP_4.setText("")
        self.lineEdit_IP_4.setObjectName("lineEdit_IP_4")
        self.label = QtGui.QLabel(self.groupBox_2)
        self.label.setGeometry(QtCore.QRect(10, 100, 311, 51))
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.pushButton_Add = QtGui.QPushButton(self.groupBox_2)
        self.pushButton_Add.setGeometry(QtCore.QRect(220, 70, 80, 25))
        self.pushButton_Add.setObjectName("pushButton_Add")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        Form.setTabOrder(self.lineEdit_IP_1, self.lineEdit_IP_2)
        Form.setTabOrder(self.lineEdit_IP_2, self.lineEdit_IP_3)
        Form.setTabOrder(self.lineEdit_IP_3, self.lineEdit_IP_4)
        Form.setTabOrder(self.lineEdit_IP_4, self.pushButton_Add)

    def retranslateUi(self, Form):
        Form.setWindowTitle(QtGui.QApplication.translate("Form", "Preferences", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_2.setTitle(QtGui.QApplication.translate("Form", "Remote filesystem", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("Form", "For NFS, Samba, CIFS remote filesystems, enter the remote machine\'s IP address here", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_Add.setText(QtGui.QApplication.translate("Form", "Add", None, QtGui.QApplication.UnicodeUTF8))

