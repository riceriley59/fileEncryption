#!/use/bin/python3

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys, getopt, os, base64

#encrypts file using sha256 hashing algorithm
def encrypt(file, password):
	print("Encrypting: " + file + '\n')
	password = password.encode()

	salt = b'\xbat\x19\xa3 \x91\x7f\xd55L\x99\x97G(\x991'

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(password))
	print("This is your Key:")
	print(key)

	open_file = open(file, 'rb')
	message = open_file.read()
	open_file.close()

	f = Fernet(key)
	encryped_message = f.encrypt(message)

	open_file2 = open(file, "wb")
	open_file2.write(encryped_message)
	open_file2.close()

	key_file = open('key.key', 'wb')
	key_file.write(key)
	key_file.close()

	print("Encrypted")

#decrypts file by hashing the password given and then comparing it to the key
#to see if they match and if they do it decrypts it
def decrypt(file, password):
	print("Decrypting: " + file)
	key_file = open('key.key', 'rb')
	file_key = key_file.read()
	key_file.close()
	print(file_key)

	password = password.encode()

	salt = b'\xbat\x19\xa3 \x91\x7f\xd55L\x99\x97G(\x991'

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(password))

	if key == file_key:
		decrypt_file = open(file, 'rb')
		encrypted_message = decrypt_file.read()
		decrypt_file.close()

		f2 = Fernet(key)
		decrypted_message = f2.decrypt(encrypted_message)

		done_file = open(file, 'wb')
		key2 = done_file.write(decrypted_message)
		done_file.close()

		print('Decrypted')
	else:
		print("Wrong Password, Try Again!")

#main function that takes argument from command line and parses it to get the information
#and do the correct interactions.
def main(argv):
	try:
		opts, args = getopt.getopt(argv,"hd:e:p:",[])
	except getopt.GetoptError:
		print('python3 encrypt.py -d(decrypt)<file> or -e(encrypt)<file> -p <password>(Mandatory)')
		sys.exit(2)
	for opt, arg in opts:
		if opt == "-p":
			password = arg
			print("Password: " + password)
			break
	for opt, arg in opts:
		if opt == '-h':
			print('python3 encrypt.py -d(decrypt)<file> or -e(encrypt)<file> -p <password>(Mandatory)')
		elif opt == "-d":
			dfile = arg
			decrypt(dfile, password)
		elif opt == "-e":
			efile = arg
			encrypt(efile, password)

if __name__ == '__main__':
	sys.exit(main(sys.argv[:]))