
class User:
    def __init__(self, userName, email, password, confirmpassword, userType):
        self.__userName = userName
        self.__email = email
        self.__password = password
        self.__confirmpassword = confirmpassword
        self.__userType = userType

    def get_userName(self):
        return self.__userName

    def get_email(self):
        return self.__email

    def get_password(self):
        return self.__password

    def get_confirmpassword(self):
        return self.__confirmpassword

    def get_userType(self):
        return self.__userType

    def set_userName(self, userName):
        self.__userName = userName

    def set_email(self, email):
        self.__email = email

    def set_password(self, password):
        self.__password = password

    def set_confirmpassword(self, confirmpassword):
        self.__confirmpassword = confirmpassword

    def set_userType(self, userType):
        self.__userType = userType