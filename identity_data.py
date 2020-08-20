#!/usr/bin/env python3
"""
______________
MIT License

Copyright (c) 2020 Julian Rösner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
____________________________
"""


from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import urllib.request


########################
#       FUNCTIONS      #
########################

# Create a new key pair
def new_keys():
	private_key = RSA.generate(4096)
	public_key = private_key.publickey()

	return private_key, public_key

# Store a key pair in files
def store_keys(private_key, pr_key_file_name, public_key, pu_key_file_name):
	with (pr_key_file_name, 'w') as pr_key_file:
		pr_key_file.write(private_key)

	with (pu_key_file_name, 'w') as pu_key_file:
		pu_key_file.write(public_key)

# Load key from file
def load_key_from_file(file_name):
	return RSA.import_key(open(file_name).read())

# Load key from url
def load_key_from_url(url):
	webUrl = urllib.request.urlopen(url)
	return RSA.import_key(webUrl.read())	

# Load keys from files
def load_keys_from_file(private_file, public_file):
	private_key = load_key_from_file(private_file)
	public_key = load_key_from_file(public_file)

	return private_key, public_key

# Function to hash data and sign it
def sign(data, private_key):
	hash_value = SHA256.new(data)
	signature = pkcs1_15.new(private_key).sign(hash_value)

	return hash_value, signature

# Check signature on a hash value with public key
def check_sig(public_key, hash_value, signature):
	try:
	    pkcs1_15.new(public_key).verify(hash_value, signature)
	    return True
	except (ValueError, TypeError):
	    return False

# Save signature and hash value to files
def save_sig_hash(signature, sig_file_name, hash_value, hash_file_name):
	with open(sig_file_name, 'w') as sig_file:
	    sig_file.write(signature.hex())

	with open(hash_file_name, 'w') as hash_file:
	    hash_file.write(hash_value.hexdigest())		

# Open signature from a file
def open_sig(sig_file_name):
	with open(sig_file_name, 'r') as sig_file:

		return bytes.fromhex(sig_file.read())

# Test if a signaturefile contains a valid signature
def test_sig_file(public_key, sig_file_name, data_file_name):
	signature = open_sig(sig_file_name)
	with open(data_file_name, 'rb') as data_file:
	    data = data_file.read()
	hash_value = SHA256.new(data)
	return check_sig(public_key, hash_value, signature)



########################
#         MAIN         #
########################
if __name__ == "__main__":
	# Get the keys
	private_key, public_key = load_keys_from_file('private_key.pem','public_key.pem')

	# Get the identity data from the file
	identity_data = b''
	with open('identity_data.txt', 'rb') as data_file:
	    identity_data = data_file.read()

	# Hash the data & sign it
	hash_value, signature = sign(identity_data, private_key)

	# Check the signature and then store hash and signature to files
	if check_sig(public_key, hash_value, signature):
		print("Everthing is fine and files are updated.")
		save_sig_hash(signature, 'signature.pem', hash_value, 'hash.pem')
	else:
	    print("The signature is not valid. Check your key pair")

	if test_sig_file(public_key, 'signature.pem', 'identity_data.txt'):
		print("Done")
	else:
		print("The stored signature seems to be broken")

