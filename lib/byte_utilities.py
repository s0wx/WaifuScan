import logging
import os
import subprocess

from lib.mongo_utilities import certificate_database


def filetype_from_bytes(data_bytes):
    """
    Check file type of bytes. Until there is no proper way, it is necessary to write to a temporary file.

    :param data_bytes: bytes data
    :return: file type
    """

    # writing temp file because file can't use bytes from stdin
    with open("cert_buffer_file", "wb") as buffer_file:
        buffer_file.write(data_bytes)

    # check type with unix file command and delete temp file afterwards
    file_type_command = subprocess.check_output("file cert_buffer_file", shell=True)
    os.unlink("cert_buffer_file")

    # only use the part with the file type from the output
    file_info = file_type_command.decode("utf-8").split(":")[-1].strip()
    return file_info.lower()


def filetype_from_path(root_path, file):
    """
    Check file type of file in provided path.

    :param root_path: used from os.walk
    :param file: used from os.walk
    :return: file type
    """

    # check type with unix file command and replace whitespaces with escaped one (required to use in subprocess)
    file_type_command = subprocess.check_output("file " + os.path.join(root_path, file).replace(' ', '\ '), shell=True)

    # only use the part with the file type from the output
    file_info = file_type_command.decode("utf-8").split(":")[-1].strip()
    return file_info.lower()


def update_missing_cert_attributes():
    """
    Add missing certificate attributes to non-matching objects. Currently the fileType.

    :return: None
    """

    capture_logger = logging.getLogger("[WaifuScan] (DB Alignment)")
    capture_logger.setLevel(level=logging.INFO)

    for doc in certificate_database.certificates_collection.find({"dataType": None}):
        file_type = filetype_from_bytes(doc["certificateBytes"])
        certificate_database.certificates_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "dataType": file_type
            }}
        )

    capture_logger.info("successfully aligned all database entries")


def export_database():
    """
    export certificate database

    :return:
    """

    capture_logger = logging.getLogger("[WaifuScan] (DB Export)")
    capture_logger.setLevel(level=logging.INFO)

    for doc in certificate_database.certificates_collection.find():
        file_bytes = doc["certificateBytes"]

        if "certificate" in doc["dataType"]:
            with open(f"ExportDB/{doc['sha256']}.crt", "wb") as byte_file:
                byte_file.write(file_bytes)
        elif "key" in doc["dataType"]:
            with open(f"ExportDB/{doc['sha256']}.txt", "wb") as byte_file:
                byte_file.write(file_bytes)
    capture_logger.info("successfully exported all database entries")
