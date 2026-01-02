#padding strategy: https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html#:~:text=PKCS5%20Padding,added%20in%20an%20unambiguous%20manner.
#8S-Boxes: https://www.oreilly.com/library/view/computer-security-and/9780471947837/sec9.3.html
#P-Box, PC1, PC2, IP, Inverse IP and EP are obtained from the lecture slides
def Read(filename):
    Text=""
    with open(filename, "r") as file:
        Text=file.read()
    return Text

def Convert_ASCII_To_Binary(Text):
    Binary=""
    for char in Text:
        ASCIIValue=ord(char)
        Binary+=bin(ASCIIValue)[2:].zfill(8) #ensure every ascii character in convert to 8-bit binary
    return Binary 

def Convert_Binary_To_ASCII(Text):
    ASCII=""
    for i in range(0,len(Text),8):
        ASCII+=chr(int(Text[i:i+8],2))
    return ASCII

def ValidateBinary(Key):
    Validate=True
    for i in Key:
        if not(i =='0' or i =='1'):
            Validate=False
    return Validate

def ValidateHexDecimal(Key):
    Validate=True
    for i in Key:
        if not(i.isdigit() or 'A'<=i<='F' or 'a'<=i<='f'):
            Validate=False
    return Validate

def ValidateDecimal(Key):
    Validate=True
    for i in Key:
        if not(i.isdigit()):
            Validate=False
    return Validate

def gettingUserDefinedKey():
    Key=""
    while(True):
        print("Please enter the key format that you want. ")
        print("1)Binary 2)Hexadecimal 3)ASCII 4)Decimal")
        Choice=input("Your Choice: ")
        if Choice =='1':
            Choice="Binary"
            Key=input("Please enter your key: ")
            if(ValidateBinary(Key)==True):
                break
            else:
                print("Invalid Output")
        
        elif Choice=='2':
            Choice="Hexadecimal"
            Key=input("Please enter your key: ")
            if(ValidateHexDecimal(Key)==True):
                break
            else:
                print("Invalid Output")

        elif Choice=='3':
            Choice="ASCII"
            Key=input("Please enter your key: ")
            break

        elif Choice=='4':
            Choice="Decimal"
            Key=input("Please enter your key: ")
            if(ValidateDecimal(Key)==True):
                break
            else:
                print("Invalid Output")
        else:
            print("Invalid Output. ")
            
    return Key, Choice

#The usage of str.zfill() built-in function is obtained from https://www.w3schools.com/python/ref_string_zfill.asp
#The usage of format() is obtained from https://www.w3schools.com/python/ref_func_format.asp
#padding the user-defined key to 64 bits
def pad_key_to_64_bits(key, key_format):
    binary_key = ""

    # Convert key to binary based on its format
    if key_format == "ASCII":
        # Convert each ASCII character to binary and join them
        for c in key:
            Binary_Form=format(ord(c), 'b') #convert each character in key to binary form then concat the str
            binary_key+=Binary_Form

    elif key_format == "Decimal":
        # Convert decimal number to binary
        binary_key =format(int(key), 'b')

    elif key_format == "Hexadecimal":
        Dec_Form=int(key,16) #convert to decimal first
        Binary_Form=format(Dec_Form, 'b') #convert to binary form
        binary_key=Binary_Form

    elif key_format == "Binary":
        # Assume key is already in binary format
        binary_key = key

    else:
        raise ValueError("Unsupported key format")

    # Ensure the key is exactly 64 bits
    if len(binary_key) < 64:
        binary_key = binary_key.zfill(64)  #apply padding on keys that's less than 64 bits

    else:
        binary_key=binary_key[:64]
    return binary_key

#string.encode(): convert string into byte representation. Those non-printable character will be presented in hexadecimal form
def PKCS_5Padding(Text):
    ASCIIPadded_Text=""
    ASCIIText=""
    block_size=8  #8 byte
    ASCIIText=Convert_Binary_To_ASCII(Text)
    Byte_Needed=block_size-(len(ASCIIText)%block_size)
    ASCIIPadded_Text=ASCIIText + chr(Byte_Needed) * Byte_Needed
    BinaryPadded_Text=Convert_ASCII_To_Binary(ASCIIPadded_Text)
    return BinaryPadded_Text, ASCIIPadded_Text.encode()

def PKCS_5Unpadding(BinaryPaddedText):
    Padded_Bit_Length=int(BinaryPaddedText[-8:],2)*8  # multiply by 8 to know how many bits are padded
    BinaryUnpaddedText=BinaryPaddedText[:-Padded_Bit_Length] #A[:-3]=A[:len(A)-3]
    return BinaryUnpaddedText

def permuted_Choice_1(key):
    Permuted_Key=""
    #The PC1 table is obtained from lec4 pg 56
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    ]
    for i in PC1:
        Permuted_Key+=key[i-1]
    return Permuted_Key 

def permuted_Choice_2(key):
    Permuted_Key=""
    #The PC2 table is obtained from lec 4 pg 57
    PC2 = [
        14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]
    for i in PC2:
        Permuted_Key+=key[i-1]
    return Permuted_Key

def leftCircularShift(shift, bit):
    return bit[shift:] + bit[:shift]

def KeyScheduling(Key, Choice):
    Binary_Key=pad_key_to_64_bits(Key,Choice)     
    PC1_Key=permuted_Choice_1(Binary_Key)
    
    #performing left shift
    Shift_Schedule=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    left_Half=PC1_Key[:28]  #extract the first 28 bits
    right_Half=PC1_Key[28:] #extract the last 28 bits
    round_Key=[]
    for shift in Shift_Schedule:
        left_Half=leftCircularShift(shift,left_Half)
        right_Half=leftCircularShift(shift,right_Half)
        combined_key=left_Half+right_Half
        
        #apply PC-2 to reduce the key to 48 bits after left shift
        PC2_Key=permuted_Choice_2(combined_key) #48-bit key
        round_Key.append(PC2_Key)
    return round_Key

def S_Box_Substitution(xor_result):
    S_Box_Output=""
    S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    # S3
    [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
    [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
    [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
    [1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]], 
    
    # S4
    [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
    [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
    [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
    [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],

    # S5
    [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
    [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
    [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
    [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],
    
    # S6
    [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
    [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
    [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
    [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],
    
    # S7
    [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
    [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
    [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
    [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],
    
    # S8
    [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
    [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
    [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
    [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]
    
    ]
    
    for i in range(8):
        #extract every 6 bits from xor-result
        Six_Bit=xor_result[(i*6): (i*6)+6] 
        First_Bit=Six_Bit[0]
        Last_Bit=Six_Bit[5]
        Middle_Bit=Six_Bit[1:5]
        row=int(First_Bit+Last_Bit, 2)
        col=int(Middle_Bit, 2)
        SValue=S_BOXES[i][row][col]
        BinaryStr=format(SValue, "04b") #convert the value obtained from S box to 4 bit binary string
        S_Box_Output+=BinaryStr  #Append it to S_Box_Output
    return S_Box_Output

def P_Box(S_Box_Output):
    P_Box_Output=""
    P_BOX = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
    ]
    for i in P_BOX:
        P_Box_Output+=S_Box_Output[i-1]
        
    return P_Box_Output

def Inverse_Permutation(Text):
    Inv_Permute=""
    IP_INVERSE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
    ]
    for i in IP_INVERSE:
        Inv_Permute+=Text[i-1]
    
    return Inv_Permute

def Expansion_Permutation(Right_Half):
    
    if(len(Right_Half)>=32):
        Expanded_Bit=""
        EP=[32,  1,  2,  3,  4,  5,  
            4,  5,  6,  7,  8,  9,  
            8,  9, 10, 11, 12, 13,  
            12, 13, 14, 15, 16, 17,  
            16, 17, 18, 19, 20, 21,  
            20, 21, 22, 23, 24, 25,  
            24, 25, 26, 27, 28, 29,  
            28, 29, 30, 31, 32, 1]
        for i in EP:
            Expanded_Bit+=Right_Half[i-1]
    else:
        print("The length of the right half is not 32 bits")
    return Expanded_Bit

def IP(PlainTextBlocks):
    IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7]
    Permuted_Str=""
    for i in IP_TABLE:
        Permuted_Str+=PlainTextBlocks[i-1]
    return Permuted_Str   

def Feistel_Func(left_Half,right_Half, Key):
    Expanded_RightBit=Expansion_Permutation(right_Half)  #48bits
    PC2_Key=Key  #48 bit keys        
    #convert binary string to decimal for both Expanded_RightBit and PC2_Key
    #perform bitwise XOR
    xor_result=int(Expanded_RightBit,2) ^ int(PC2_Key,2)
            
    #convert the xor_result back to binary string in 48 bits
    xor_result=bin(xor_result)[2:].zfill(48)
    S_Box_Output=S_Box_Substitution(xor_result)
    P_Box_Output=P_Box(S_Box_Output)
    #perform XOR of the left_half and P_Box_Output
    FinalXOR=int(left_Half, 2) ^ int(P_Box_Output, 2)
    #convert the FinalXOR back to binary string in 32 bits and remove 0b at the front
    FinalXOR=bin(FinalXOR)[2:].zfill(32)
    return FinalXOR

def splitLHblocks(PlainTextBlock):
    left_Half=""
    right_Half=""
    left_Half+=PlainTextBlock[:32]  #first 32 bits
    right_Half+=PlainTextBlock[32:] #last 32 bits
    return left_Half, right_Half

def Divide_Text_To_Blocks(Text):
    block_size=64
    block=[]
    for i in range(0,len(Text),block_size):
        block.append(Text[i:i+block_size])
    return block

def DES_Encryption(PlainText):
    CipherText=""
    BinaryCipherText=""
    BinaryPlainText=Convert_ASCII_To_Binary(PlainText)
    BinaryPadded_Text, ASCIIPadded_Text=PKCS_5Padding(BinaryPlainText)
    BinaryPlainText_Blocks=Divide_Text_To_Blocks(BinaryPadded_Text)
    Key, Key_Format=gettingUserDefinedKey()
    Round_Key=KeyScheduling(Key, Key_Format)
    for index,block in enumerate(BinaryPlainText_Blocks):
        Initial_Permuted_Binary=IP(block)
        Left_Half, Right_Half=splitLHblocks(Initial_Permuted_Binary)
        for roundKey in Round_Key:
            FinalXOR=Feistel_Func(Left_Half, Right_Half, roundKey)
            Left_Half=Right_Half
            Right_Half=FinalXOR
        Left_Half,Right_Half=Right_Half,Left_Half
        Concat_Left_Right=Left_Half+Right_Half
        Inv_IP=Inverse_Permutation(Concat_Left_Right)
        BinaryCipherText+=Inv_IP
        CipherText+=hex(int(Inv_IP,2))[2:]
    with open("DESCipher.txt", "w") as file:
        file.write(CipherText)
    return BinaryCipherText


    
def DES_Decryption(CipherText):
    PlainText=""
    PlainTextBinary=""
    Key, KeyFormat=gettingUserDefinedKey()
    Round_Key=KeyScheduling(Key,KeyFormat)
    BinaryCipherText_Blocks=Divide_Text_To_Blocks(CipherText)
    for block in BinaryCipherText_Blocks:
        Initial_Permuted_Binary=IP(block)
        Left_Half, Right_Half=splitLHblocks(Initial_Permuted_Binary)
        for roundKey in reversed(Round_Key):
            FinalXOR=Feistel_Func(Left_Half,Right_Half,roundKey)
            Left_Half=Right_Half
            Right_Half=FinalXOR
        Left_Half, Right_Half=Right_Half,Left_Half
        Concat_Left_Right=Left_Half+Right_Half
        Inv_P=Inverse_Permutation(Concat_Left_Right)
        PlainTextBinary+=Inv_P
    PlainTextBinary=PKCS_5Unpadding(PlainTextBinary)
    PlainText=Convert_Binary_To_ASCII(PlainTextBinary)
    with open("DESPlainText.txt", "w") as file:
        file.write(PlainText)
        print("Text has been sucessfully decrypted!")
    return PlainText
    
PlainText=Read("DES-test2025.txt")
CipherText=DES_Encryption(PlainText)
User_Choice=input("Do you want to perform decryption(Y/N): ")
if(User_Choice=='y' or User_Choice=='Y'):
    print("\nPlease enter the same key and key format that you entered for decryption. \n")
    RecoveredText=DES_Decryption(CipherText)
