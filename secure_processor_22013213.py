import sys
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key():
    #Generate the private key which takes 
    #In key generation process:
    #two large random prime numbers are picked, p and q
    #n=p*q and Euler's Totient Func, (p-1)(q-1) will be computed
    #using the given public exponent, e, d will be computed by extended euclidean algorithm
    #all other value that are part of private keys such as p,q,n and d will be stored in private key object
    private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    #only n and e will be stored in the public key object
    public_key=private_key.public_key() #export public key from private key
    
    #saving keys to .pem file
    #serialization.Encoding.PEM means encode the key in Base64 format with header and footer lines
    #Base64 is a format of encoding binary data to ASCII text
    
    with open("private.pem", "wb") as file:
        #serialization: a process that converts object state data into a format that can be stored
        #private_key.private_bytes(...) serializes(convert) the key to byte
        #3 parameters inside the function
        #encoding tells how to encode the data
        #serialization.Encoding.PEM converts the byte to PEM format which is base64 surrounded by header and footer
        #serialization.PrivateFormat.TraditionalOpenSSL structures the private key format in PKCS1
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM, #encode in Base 64 format
            format=serialization.PrivateFormat.TraditionalOpenSSL, #TraditionalOpenSSL=PKCS1 format
            encryption_algorithm=serialization.NoEncryption()) ) #private key is stored without encryption

    with open("public.pem", "wb") as file:
        file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM, #encode in Base 64(ASCII Text)
            format=serialization.PublicFormat.PKCS1) ) 

def encrypt_document(input_file, public_key_file, output_file):
    
    #obtain the plain text from the file
    with open(input_file, "r") as file:
        PlainText=file.read()
        PlainText=PlainText.encode()  #convert plaintext to byte in UTF-8
        
    #Apply OAEP padding before encryption
    #Purpose: enhance randomness in the data block so that the ciphertext generated each time is different even the key is the same
    #This mitigates the risk of attacker manipulating the ciphertext
    #How OAEP padding works internally:
    #a random seed is generated
    #data block consists of the hashed label, padding 0s, seperator byte 0x01 and the message
    #MGF1 is applied to seed then XOR with the data block
    #This forms a masked DB
    #The seed is then XORed with the mask generated from MGF1 to form masked seed
    #the final encoded message is formed by concatenating 0x00(positive sign), masked seed, masked DB
    #the final encoded message is then involved in encryption
    #this enhances randomness in the data block
    padding_scheme=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), # use SHA256 to generate mask
        algorithm=hashes.SHA256(),  #hash the label using SHA256
        label=None
    )
    
    #load the public key from public.pem file
    with open(public_key_file, "rb") as file:
        public_key=serialization.load_pem_public_key(file.read()) #This converts the public key in the pem file to public key object
    
    #encryp the plaintext
    CipherText=public_key.encrypt(PlainText, padding_scheme)
    
    #write the plaintext to the file
    with open(output_file, "wb") as file:
        file.write(base64.b64encode(CipherText))  #encode the raw byte to base64 format

def decrypt_document(encrypted_file, private_key_file):
    
    #read the cipher text and decode it
    with open(encrypted_file, "rb") as file:
        CipherText=file.read()
        CipherText=base64.b64decode(CipherText)
    
    #unpadding after decryption with this padding scheme    
    padding_applied=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    
    #load the private key from private.pem file
    with open(private_key_file, "rb") as file:
        private_key=serialization.load_pem_private_key(file.read(), password=None)
    
    PlainText=private_key.decrypt(CipherText, padding_applied)
    PlainText=PlainText.decode()  #The plaintext is encoded to byte previously, now revert it back
    
    #print to the console
    print(PlainText)
    
#hash the plaintext
#apply padding to the hashed plaintext
#encrypt the hashed plaintext with private key
#save the signature in digital_signature.sig
def sign_document(input_file, private_key_file, signature_file):
    with open(input_file, "rb") as file:
        PlainText=file.read()
    
    #apply PSS padding before encrypting the hashed message
    #purpose: prevent attacker forging signature
    #How pss works:
    #hash the message
    #generate a random salt based on the given length
    #build M' which consists of Padding, hash(M), and salt
    #hash(M')
    #create EM which consists of Padding, seperator 0x01, salt and hash(M')
    #Mask padding + seperator + salt by repeatedly hashing the block with incrementing counter
    #XOR the mask with DB(padding + seperator + salt)
    #Final EM=MaskedDB + Hash(M') + bc(0xBC)
    #bc: represents the end of the block    
    padding_scheme=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),  #use the hash func- sha256 for masking
        salt_length=padding.PSS.MAX_LENGTH  #generate the salt based on the max length
    )
    
    #load the private key from .pem file
    #creates a private_key object which can be used for encrypting EM to generate signature
    with open(private_key_file, "rb") as file:
        Private_Key=serialization.load_pem_private_key(file.read(), password=None)
    
    #use private key for signature
    S=Private_Key.sign(PlainText, padding_scheme, hashes.SHA256())
    
    with open(signature_file, "wb") as file:
        file.write(base64.b64encode(S))  #store the signature in base64
        
def verify_sign(input_file, signature_file, public_key_file):
    #load the public key from .pem file
    #decrypt the signature using public key
    with open(public_key_file, "rb") as file:
        public_key=serialization.load_pem_public_key(file.read())

    with open(signature_file, "rb") as file:
        Signature=file.read()
        Signature=base64.b64decode(Signature) #convert back to raw byte
    
    with open(input_file, "rb") as file:
        PlainText=file.read()
     
    #the padding scheme applied for signature must be the same here for unpadding  
    padding_scheme=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    
    try:
        public_key.verify(Signature, PlainText, padding_scheme, hashes.SHA256())
        print("Verification Success. ")
    
    except:
        print("Verfication failure.")
                  

if(len(sys.argv) != 2):
    print("Not enough argument. ")

else:
    if(sys.argv[1]=="KeyGen"):
        try:
            generate_key()
            print("Keys generated successfully! ")
        except:
            print("Error in generating key. ")
    
    elif(sys.argv[1]=="Enc"):
        try:
            encrypt_document("confidential_message.txt", "public.pem", "secure_message.enc")
            print("Successful Encryption!")
        except:
            print("Error in encryption. ")
    
    elif(sys.argv[1]=="Dec"):
        decrypt_document("secure_message.enc", "private.pem")
        
    elif(sys.argv[1]=="Sig"):
        try:
            sign_document("confidential_message.txt", "private.pem", "digital_signature.sig")
            print("Signature generated. ")
        except:
            print("Failure in generating signature. ")
        
    elif(sys.argv[1]=="Ver"):
        verify_sign("confidential_message.txt","digital_signature.sig","public.pem")
        
    else:
        print("Invalid argument")