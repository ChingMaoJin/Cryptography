#Letter Freq Table is from https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
#I learnt the usage of zip() function from https://www.w3schools.com/python/ref_func_zip.asp
import matplotlib.pyplot as plt

#open and read the file. Remove any leading space and return the reading output
def read_cipherText(filename):
    with open(filename, 'r') as file:
        CipherText=file.read()
        return CipherText  

def Calculating_Freq(CipherText):
    char_freq={} #create a empty dictionary
    CipherText=CipherText.lower() #convert to lower case
    TotalFreq=0
    for char in CipherText:
        if(char.isalpha()):
            if char in char_freq:
                char_freq[char]+=1
                
            else:
                char_freq[char]=1
            TotalFreq+=1
    for char in char_freq:
        char_freq[char]=char_freq[char]/TotalFreq #calculating relative freq   
    return char_freq

def SortDictionary(items):
    SortedDic=dict(sorted(items.items(), key=lambda item:item[1], reverse=True))
    return SortedDic

def Mapping(SortedDic):
    ENGLISH_FREQ_ORDER = "etaoinsrhdlucmfywgpbvkxqjzETAOINSRHDLUCMFYWGPBVKXQJZ"
    CipherLetters=list(SortedDic.keys())
    for key in SortedDic:
        CipherLetters.append(key.upper())
    MappingDic=dict(zip(CipherLetters,ENGLISH_FREQ_ORDER))  #to map each element from a list to another element from another list
    return MappingDic

# str.join() : joins all the elements in a tuple
#Dict.get(key): return the value of the item with specific key    
def Decrypting(MappingDic, CipherText):
    DecryptedText=""
    for letter in CipherText:
        DecryptedText +=MappingDic.get(letter,letter)
    DecryptedText=list(DecryptedText) #convert to list then iterate through each char
    Replace_Mapping ={
    'r': 'n', 'R': 'N',
    'i': 'r', 'I': 'R',
    's': 'i', 'S': 'I',
    'd': 'l', 'D': 'L',
    'l': 'd', 'L': 'D',
    'f': 'g', 'F': 'G',
    'y': 'm', 'Y': 'M',
    'w': 'p', 'W': 'P',
    'n': 's', 'N': 'S',
    'm': 'f', 'M': 'F',
    'g': 'y', 'G': 'Y',
    'p': 'b', 'P': 'B',
    'x': 'z', 'X': 'Z',
    'b': 'w', 'B': 'W',
    'z': 'x', 'Z': 'X'
    }
    for index, char in enumerate(DecryptedText):
        for key,value in Replace_Mapping.items():
            if char==key:
                DecryptedText[index]=value

    DecryptedText="".join(DecryptedText)
    
    with open("Letter_Freq_Analysis_DecryptedText.txt", "w") as file:  
        file.write(DecryptedText)

def DisplayFreqChart(SortedDic):
    X=list(SortedDic.keys())
    Y=list(SortedDic.values())              
    plt.bar(X, Y)
    plt.show()

                  
CipherText=read_cipherText("cipher2025.txt")
Char_Freq=Calculating_Freq(CipherText)
SortedDic=SortDictionary(Char_Freq)
DisplayFreqChart(SortedDic)
MappingDic=Mapping(SortedDic)
Decrypting(MappingDic, CipherText)

        