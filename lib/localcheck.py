import hashlib
import os
import shutil
from sys import platform

def calculate_sha256_from_bytes(byte_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_data)
    return sha256_hash.hexdigest()

def getlinuxcerts():
    #Dort abgelagert standardmäßig auf Linux
    if os.path.isfile('/etc/ssl/certs/ca-certificates.crt'):
        shutil.copy('/etc/ssl/certs/ca-certificates.crt', '../OSCerts')

def splitcerts(certificates):
    #Separiert die einzelnen Zertifikate aus der Hauptdatei
    separator = '\n-----END CERTIFICATE-----'
    certs = certificates.split(separator)

    return [cert + separator for cert in certs][:-1]


def checkos():
    if platform == "linux" or platform == "linux2":
        return 0
    elif platform == "darwin":
        #MacOS
        return 1
    elif platform == "win32":
        return 2

def checkagainstcerts(encodednew):
    directory = 'CertificateFolder'
    if checkos() == 0 or checkos() == 1:
        return not os.path.isfile(f'{directory}/{encodednew}.crt')
    if checkos() == 2:
        return not os.path.isfile(f'{directory}\{encodednew}.crt')
def linuxmain():
    if not os.path.isdir('../CertificateFolder'):
        os.mkdir('../CertificateFolder')
    #Extra Ordner für
    if not os.path.isdir('../OSCerts'):
        os.mkdir('../OSCerts')

    getlinuxcerts()

    if os.path.isfile('../OSCerts/ca-certificates.crt'):
        f = open('../OSCerts/ca-certificates.crt', "r")

        certs = splitcerts(f.read())

        for cert in certs:
            encoded = cert.encode()
            comp = calculate_sha256_from_bytes(encoded)
            if(checkagainstcerts(comp)):

                with open(f'../CertificateFolder/{comp}.crt', 'w') as f:

                    f.write(cert)



def windowsmain():
    if not os.path.isdir('../CertificateFolder'):
        os.mkdir('../CertificateFolder')
    #Extra Ordner für
    if not os.path.isdir('../OSCerts'):
        os.mkdir('../OSCerts')


    return
def macmain():
    return

def localcheck():

    if checkos() == 0:
        linuxmain()
    elif checkos() == 1:
        macmain()
    elif checkos() == 2:
        windowsmain()








