import hashlib


def calculate_sha256_from_bytes(byte_data):
    """
    Calculate SHA256 Hash of ByteData

    :param byte_data: byte data of file
    :return: hash of file content
    """

    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()
