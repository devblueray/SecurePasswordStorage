from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import boto3
from patientpop_python_utils import lambda_utils as lu
import os
import argparse
import click 

class PasswordHasher:
    # 1. Standard __init__stuff (set variables for boto clients/resources, etc)
    # 2. self.key = the hash key to use, it's stored in parameter store with it's own kms key
    def __init__(self):
        os.environ['ENV'] = 'stage'
        client = lu.LambdaUtils()
        secrets, err = client.get_secrets(['/passwordmanager/hashkey'])
        self.BLOCK_SIZE = 32 # Bytes
        self.key = secrets['/passwordmanager/hashkey']
        self.storage = boto3.resource('dynamodb') 
        self.kmsClient = boto3.client('kms')
        self.table = self.storage.Table('passwordstorage')
        self.cipher = AES.new(self.key.encode('utf8'), AES.MODE_ECB)
    #This method gets invoked from the encode method and is fed a hex string to encrypt using the KMS key
    def kmsEncrypt(self,hex):
        ciphertext = self.kmsClient.encrypt(
            KeyId='d76d0d5b-14e5-4dfb-aab8-15954ec6bc71',  #KMS key id
            Plaintext=hex,
        )
        self.storage_write(self.id, ciphertext["CiphertextBlob"].hex()) #Turn binary output to hex.    
    
    #Write client id and KMS encrypted password to dynamodb
    def storage_write(self, id, kmsEncryptedHex):
        self.table.put_item(
            Item={
                'id': self.id,
                'password': kmsEncryptedHex
            }
        )    
    
    # This method gets the data from dynano based on the clientId and returns it (at this point the data is in hex form)
    def storage_read(self,id):
        data = self.table.get_item(
            Key={
                'id': id
            }
        )
        item = data['Item']
        password = item['password']
        return password #Hex version

    #This method gets invoked from the decode method and is fed a client id.  
    def kmsDecrypt(self, id):
        ciphertext = self.storage_read(id) #Lookup hex key with client id 
        binCipherText = bytes.fromhex(ciphertext) # Convert hex to binary for use with kms.decrypt
        response = self.kmsClient.decrypt(
            CiphertextBlob=binCipherText
        )
        return response['Plaintext'].decode('utf-8') #Get KMS decrypted secret back from   



    def encode(self, id, password):
        self.id = id
        msg = self.cipher.encrypt(pad(password.encode('ascii'), self.BLOCK_SIZE))
        self.kmsEncrypt(msg.hex())
    
    def decode(self, id):
        data = self.kmsDecrypt(id)
        binmsg = bytes.fromhex(data)
        msg_dec = self.cipher.decrypt(binmsg)
        decrypted = unpad(msg_dec, self.BLOCK_SIZE)
        return decrypted.decode('ascii')

@click.command()
@click.option('--method', help='encode or decode')
@click.option('--id', help='Client Id')
@click.option('--password', help='Enter password if creating new client')    

def main(method='', id='', password=''):
    pwh = PasswordHasher()
    if method == 'encode':
        if password == '':
            print("BLANK PASSWORD")
        else:
            pwh.encode(id, password)
    else:
        print(pwh.decode(id))

if __name__ == "__main__":
    main()

