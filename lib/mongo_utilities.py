from pymongo import MongoClient


class CertificateDatabase:
    def __init__(self, host="localhost", port=27017):
        self.__db_client = MongoClient(host=host, port=port)
        self.__db = self.__db_client["WaifuScan"]
        self.certificates_collection = self.__db.certificates
        self.update_database_config()

    def update_database_config(self):
        # Certificates Collection
        self.certificates_collection.create_index("certificateSHA256", unique=True)
