from pymongo import MongoClient


class CertificateDatabase:
    def __init__(self, host="localhost", port=27017):
        self.__db_client = MongoClient(host=host, port=port)
        self.__db = self.__db_client["WaifuScan"]
        self.certificates_collection = self.__db.certificates
        self.update_database_config()

    def update_database_config(self):
        # Certificates Collection
        self.certificates_collection.create_index("sha256", unique=True)

    def add_certificate(self, certificate_complete, logger):
        if not self.certificates_collection.find_one({"sha256": certificate_complete["sha256"]}):
            self.certificates_collection.insert_one(certificate_complete)
            logger.info(f"Saved certificate {certificate_complete['sha256']} to database")


certificate_database = CertificateDatabase()


def database_setup():
    global certificate_database
    return

