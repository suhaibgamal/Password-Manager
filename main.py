from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget, QLabel, QLineEdit, QMessageBox, QCheckBox, QTableWidget, QTableWidgetItem, QInputDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtSql import QSqlDatabase, QSqlQuery
from random import choice, choices, shuffle
import re
import os.path
from sys import exit
from cryptography.fernet import Fernet

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager 3.0")
        self.resize(600, 400)
        icon_path = os.path.join(os.path.dirname(__file__), "resources", "icon.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setFixedSize(620, 420)
        

        # Create pages
        self.stacked_widget = QStackedWidget()
        self.main_page = QWidget()
        self.add_password_page = QWidget()
        self.show_password_page = QWidget()
        self.modify_password_page = QWidget()

        # Style
        self.stacked_widget.setStyleSheet("""
        QPushButton {
            background-color: #04AA6D;
            border: none;
            color: white;
            padding: 20px 50px;
            text-align: center;
            border-radius: 20px;
        }
        """)

        self.init_ui()
        self.functions()

    def init_ui(self):
        self.create_main_page()
        self.create_add_password_page()
        self.create_show_password_page()
        self.create_modify_password_page()

        self.stacked_widget.addWidget(self.main_page)
        self.stacked_widget.addWidget(self.add_password_page)
        self.stacked_widget.addWidget(self.show_password_page)
        self.stacked_widget.addWidget(self.modify_password_page)

        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

    def create_main_page(self):
        self.add_button = QPushButton("Add Password")
        self.show_button = QPushButton("Show Saved Passwords")
        self.modify_button = QPushButton("Modify Password")
        self.generate_password_button = QPushButton("Generate Password")
        self.exit_button = QPushButton("Exit")

        self.add_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        self.show_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        self.modify_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(3))
        self.generate_password_button.clicked.connect(self.generate_password_copy_label)
        self.exit_button.clicked.connect(lambda: exit())

        layout = QVBoxLayout()
        for button in [self.add_button, self.show_button, self.modify_button, self.generate_password_button, self.exit_button]:
            row = QHBoxLayout()
            row.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
            layout.addLayout(row)

        self.main_page.setLayout(layout)

    def create_add_password_page(self):
        self.add_password_page_username_label = QLabel("Email or Username:")
        self.add_password_page_username_input = QLineEdit()
        self.add_password_page_username_input.setPlaceholderText("suhaib28@gmail.com")
        
        self.add_password_page_password_label = QLabel("Password:")
        self.add_password_page_password_input = QLineEdit()
        self.add_password_page_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.add_password_page_password_show_checkbox = QCheckBox("Show Password")
        self.add_password_page_password_show_checkbox.stateChanged.connect(self.show_passwords_chars)

        self.add_password_page_service_label = QLabel("Service Name:")
        self.add_password_page_service_input = QLineEdit()
        self.add_password_page_service_input.setPlaceholderText("#Optional, Can be left empty")

        self.add_password_page_back_button = QPushButton("Back to Main Page")
        self.add_password_page_back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))

        self.add_password_page_add_button = QPushButton("Add")
        self.add_password_page_add_button.clicked.connect(self.add_password)

        layout = QVBoxLayout()
        rows = [
            (self.add_password_page_username_label, self.add_password_page_username_input),
            (self.add_password_page_password_label, self.add_password_page_password_input, self.add_password_page_password_show_checkbox),
            (self.add_password_page_service_label, self.add_password_page_service_input),
            (self.add_password_page_add_button,),
            (self.add_password_page_back_button,)
        ]

        for widgets in rows:
            row = QHBoxLayout()
            for widget in widgets:
                row.addWidget(widget)
            layout.addLayout(row)

        self.add_password_page.setLayout(layout)

    def create_show_password_page(self):
        self.show_password_page_table = QTableWidget()
        self.show_password_page_table.setColumnCount(4)
        self.show_password_page_table.setHorizontalHeaderLabels(["ID", "Username", "Password", "Service Name"])
        self.show_password_page_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.show_password_page_table.horizontalHeader().setSectionResizeMode(self.show_password_page_table.horizontalHeader().ResizeMode.Stretch)
        
        self.show_password_page_back_button = QPushButton("Back to Main Page")
        self.show_password_page_back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))

        self.show_password_page_delete_button = QPushButton("Delete Password")
        self.show_password_page_delete_button.clicked.connect(self.delete_password)

        self.show_password_page_show_button = QPushButton("Show Password")
        self.show_password_page_show_button.clicked.connect(self.show_password)

        layout = QVBoxLayout()
        layout.addWidget(self.show_password_page_table)

        button_row = QHBoxLayout()
        for button in [self.show_password_page_back_button, self.show_password_page_delete_button, self.show_password_page_show_button]:
            button_row.addWidget(button)

        layout.addLayout(button_row)
        self.show_password_page.setLayout(layout)

    def create_modify_password_page(self):
        self.modify_password_page_username_label = QLabel("Email or Username:")
        self.modify_password_page_username_input = QLineEdit()
        self.modify_password_page_username_input.setPlaceholderText("suhaibgamal28@gmail.com")

        self.modify_password_page_new_password_label = QLabel("New Password:")
        self.modify_password_page_new_password_input = QLineEdit()
        self.modify_password_page_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.modify_password_page_checkBox = QCheckBox("Show Password")
        self.modify_password_page_checkBox.stateChanged.connect(self.show_passwords_chars)

        self.modify_password_page_change_button = QPushButton("Change Password")
        self.modify_password_page_change_button.clicked.connect(self.modify_password)

        self.modify_password_page_back_button = QPushButton("Back to Main Page")
        self.modify_password_page_back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))

        layout = QVBoxLayout()
        rows = [
            (self.modify_password_page_username_label, self.modify_password_page_username_input),
            (self.modify_password_page_new_password_label, self.modify_password_page_new_password_input, self.modify_password_page_checkBox),
            (self.modify_password_page_change_button,),
            (self.modify_password_page_back_button,)
        ]

        for widgets in rows:
            row = QHBoxLayout()
            for widget in widgets:
                row.addWidget(widget)
            layout.addLayout(row)

        self.modify_password_page.setLayout(layout)

    def functions(self):
        if not self.initialize_db():
            QMessageBox.critical(self, "Error", "Failed to connect to the database.")
            exit()
        self.create_table()
        self.prompt_master_password_outside()
        self.load_tables()
    
    def show_passwords_chars(self):
        if self.add_password_page_password_show_checkbox.isChecked() == True:
            self.add_password_page_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.add_password_page_password_input.setEchoMode(QLineEdit.EchoMode.Password)    
        if self.modify_password_page_checkBox.isChecked() == True:
            self.modify_password_page_new_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.modify_password_page_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)    
        
    def load_tables(self):
        self.show_password_page_table.setRowCount(0)
        query = QSqlQuery("SELECT * FROM passwords")
        row = 0
        while query.next():
            password_id = query.value(0)
            username = query.value(1)
            service = query.value(3)
            
            self.show_password_page_table.insertRow(row)
            
            self.show_password_page_table.setItem(row, 0, QTableWidgetItem(str(password_id)))
            self.show_password_page_table.setItem(row, 1, QTableWidgetItem(username))
            self.show_password_page_table.setItem(row, 2, QTableWidgetItem(("*" * 12)))
            self.show_password_page_table.setItem(row, 3, QTableWidgetItem(service))
            
            row+=1
        
    def add_password(self):
        username = self.add_password_page_username_input.text()
        service = self.add_password_page_service_input.text()
        password = self.add_password_page_password_input.text()
        if self.add_password_page_username_input.text():
            if self.validate_password(password) == False:
                QMessageBox.warning(self.stacked_widget, "Error", "Password must be at least 12 characters long and at least have one uppercase letter, one lowercase letter, one digit and one special character")
                auto_generate = QMessageBox.question(self.stacked_widget, "Auto Fill Password", "Click Yes To Auto-Generate Password For You",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
                if auto_generate == QMessageBox.StandardButton.Yes:
                    password = self.generate_secure_password()
                    self.add_password_page_password_input.setText(password)
                else:
                    self.add_password_page_password_input.setFocus()
                    return

            query = QSqlQuery()
            query.prepare("""
                        INSERT INTO passwords 
                        (username, password,service)
                        VALUES(?,?,?)
                        
                        """)
            query.addBindValue(username)
            query.addBindValue(self.encrypt_password(password))
            query.addBindValue(service)
            query.exec()
            QMessageBox.information(self.stacked_widget, "Information", "Credentials Added Successfully!")
            for _ in [self.add_password_page_username_input, self.add_password_page_password_input, self.add_password_page_service_input]:
                _.clear()
            self.add_password_page_username_input.setFocus()
            self.load_tables()
            
        else:
            QMessageBox.warning(self.stacked_widget, "Error", "Username box can't be empty!!")
            self.add_password_page_username_input.setFocus()
            
    def show_password(self):
        selected_rows = [i.row() for i in self.show_password_page_table.selectedItems()]
        if not selected_rows:
            QMessageBox.warning(self.stacked_widget, "Error", "Select a row or more to show password")
            return False
        if self.prompt_master_password_inside():
            usernames = [(self.show_password_page_table.item(i, 1).text()) for i in selected_rows]
            passwords = []
            query = QSqlQuery("SELECT password FROM passwords WHERE id = ?")
            for i in selected_rows:
                query.addBindValue(int(self.show_password_page_table.item(i, 0).text()))
                query.exec()
                query.next()
                password = self.decrypt_password(query.value(0))
                passwords.append(password)
            
            for username, password in zip(usernames, passwords):
                self.username_password_msgbox = QMessageBox.information(
                    self.stacked_widget, 
                    "Password", 
                    f"Username: {username}\nPassword: {password}\n\nClick OK To Copy Password"
                )
                if self.username_password_msgbox == QMessageBox.StandardButton.Ok:
                    clipboard = QApplication.clipboard()
                    clipboard.setText(password)
                    
    def delete_password(self):
            selected_rows = [i.row() for i in self.show_password_page_table.selectedItems()]
            if not selected_rows:
                QMessageBox.warning(self.stacked_widget, "Error", "Select a row or more to delete")
                return
            confirm = QMessageBox.question(self.stacked_widget,"Confirm","Delete Selected Credentials?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                ids = [int(self.show_password_page_table.item(i,0).text()) for i in selected_rows]
                for password_id in ids:    
                    query = QSqlQuery()
                    query.prepare("""
                                
                                Delete FROM passwords WHERE id = ?
                                
                                """)
                    query.addBindValue(password_id)
                    query.exec()
                    self.load_tables()
                    
    def modify_password(self):
        username = self.modify_password_page_username_input.text()
        check_query = QSqlQuery("SELECT username FROM passwords")
        new_password = self.modify_password_page_new_password_input.text()
        username_found = False
        i = 0
        while check_query.next():
            if username == check_query.value(i):
                username_found = True
                i+=1
        if username_found:
            if self.prompt_master_password_inside():
                    if self.validate_password(new_password) == False:
                        QMessageBox.warning(self.stacked_widget, "Error", "Password must be at least 12 characters long and at least have one uppercase letter, one lowercase letter, one digit and one special character")
                        auto_generate = QMessageBox.question(self.stacked_widget, "Auto Fill Password", "Click Yes To Auto-Generate Password For You",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
                        if auto_generate == QMessageBox.StandardButton.Yes:
                            new_password = self.generate_secure_password()
                            self.modify_password_page_new_password_input.setText(new_password)
                        else:
                            self.modify_password_page_new_password_input.clear()
                            self.modify_password_page_new_password_input.setFocus()
                            return
                    query = QSqlQuery()
                    query.prepare("""
                                UPDATE passwords SET password = ? WHERE username = ?
                                """)
                    query.addBindValue(self.encrypt_password(new_password))
                    query.addBindValue(username)
                    query.exec()
                    self.load_tables()
                    QMessageBox.information(self.stacked_widget, "Information", "Password Changed Successfully!")
                    self.modify_password_page_username_input.clear()
                    self.modify_password_page_new_password_input.clear()
                    return
        else:
            QMessageBox.warning(self.stacked_widget, "Warning", "Username was not found!")
            self.modify_password_page_username_input.setFocus()
        
    def validate_password(self, password: str):
        if len(password) < 12:
            return False
        if not re.search(r"[a-z]",password):
            return False
        if not re.search(r"[A-Z]",password):
            return False
        if not re.search(r"\d",password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True
        
    def generate_secure_password(self):
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
        lower = "abcdefghijklmnopqrstuvwxyz" 
        digits = "0123456789"
        special = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
        password = [
            choice(upper),
            choice(lower),
            choice(digits),
            choice(special),
        ]

        all_characters = upper + lower + digits + special
        password += choices(all_characters, k=12-len(password))

        shuffle(password)

        return ''.join(password)
        
    def generate_password_copy_label(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.generate_secure_password())
        QMessageBox.information(self.stacked_widget, "Informatioin", "Password Copied To Clipboard")
            
    def prompt_master_password_inside(self):
        master_password = self.master_password()
        if master_password is None:
            return False 
        entered_password, ok = QInputDialog.getText(self, "Master Password", "Enter your Master Password:",)
        if ok and entered_password == master_password:
            return True
        QMessageBox.critical(self.stacked_widget, "Error", "Master Password is incorrect!")
        return False
    
    def prompt_master_password_outside(self):  
        master_password = self.master_password()
        if master_password is None:
            return False 
        entered_password, ok = QInputDialog.getText(self, "Master Password", "Enter your Master Password:",)
        if ok and entered_password == master_password:
            return True
        QMessageBox.critical(self.stacked_widget, "Error", "Master Password is incorrect!")
        exit()
    
    def load_key(self):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    
    def encrypt_password(self ,password: str):
        key = self.get_or_create_key()
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password.decode()

    def decrypt_password(self, encrypted_password: str):
        key = self.get_or_create_key()
        fernet = Fernet(key)
        decrypted_password = fernet.decrypt(encrypted_password.encode())
        return decrypted_password.decode()
    
    def get_or_create_key(self):
        if not os.path.exists("secret.key"):
            self.generate_key()
        return self.load_key()
    
    def generate_key(self):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)     
            
    def initialize_db(self):
        db = QSqlDatabase.addDatabase("QSQLITE")
        db.setDatabaseName("passwords.db")
        if not db.open():
            QMessageBox.critical(self, "Database Error", "Failed to connect to the database.")
            return False
        return True
    
    def create_table(self):  
        query = QSqlQuery()
        
        sql_command1 = """
                CREATE TABLE IF NOT EXISTS master_password (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            master_password TEXT NOT NULL UNIQUE
                        );
                    """

        

        sql_command2 = """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                service TEXT
            );
        """
        if query.exec(sql_command1) and query.exec(sql_command2):
            return True
        QMessageBox.critical(self.stacked_widget, "Error", f"Failed to create table: {query.lastError().text()}")
        return False

    def master_password(self):
        query = QSqlQuery()
        master_password = None
        
        query.prepare("SELECT master_password FROM master_password LIMIT 1")
        
        if not query.exec() and query.next():
            QMessageBox.critical(self.stacked_widget, "Error", f"Failed to execute SELECT query: {query.lastError().text()}")
            return None
        
        if query.exec() and query.next():
            master_password = self.decrypt_password(query.value(0))
            return master_password
        
        if master_password:
            return master_password
        
        generate_master_password = QMessageBox.question(self.stacked_widget, "Master Password", "Do you want to create a Master Password?", QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
        if generate_master_password == QMessageBox.StandardButton.Yes:
            new_master_password, ok = QInputDialog.getText(self.stacked_widget, "Master Password", "Enter your Master Password:",)
            if ok and new_master_password:
                insert_query = QSqlQuery()
                insert_query.prepare("""
                            INSERT INTO master_password 
                            (master_password)
                            VALUES(?)
                            
                            """)
                insert_query.addBindValue(self.encrypt_password(new_master_password))
                if insert_query.exec():
                    QMessageBox.information(self.stacked_widget, "Welcome", "Welcome to Password Manager 3.0\n\nClick OK to continue")
                else:
                    QMessageBox.critical(
                        self.stacked_widget,
                        "Error",
                        f"Failed to save Master Password: {insert_query.lastError().text()}"
                    )
            else:
                QMessageBox.warning(self.stacked_widget, "Warning", "Master Password creation canceled.")
                return None
        elif generate_master_password == QMessageBox.StandardButton.No:
            QMessageBox.warning(self.stacked_widget, "Warning", "Master Password is important!")
            return None
        return None


if __name__ == "__main__":
    app = QApplication([])
    main_window = App()
    main_window.show()
    app.exec()
    
        
        




