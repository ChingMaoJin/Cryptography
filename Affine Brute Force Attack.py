#dictionary.items(): return key value pair in a tuple https://www.w3schools.com/python/ref_dictionary_items.asp
#map(func, iterable): iterable is sent as the parameter to func for execution https://www.w3schools.com/python/ref_func_map.asp
def Read(filename):
    with open(filename, "r") as file:
        CipherText=file.read()
    return CipherText

def loadCommonWords():
    CommonEnglishWords=["the", "and", "to", "of", "a", "in"]
    return CommonEnglishWords

def pairing(ValuesOfA, ValuesOfB):
    Pair=[]
    for A in ValuesOfA:
        for B in ValuesOfB:
            Pair.append((A,B))
    return Pair
    

def Decrypting(ValuesOfA,ValuesofB,CipherText):
    FreqDic={}
    for A in ValuesOfA:
        A_Inv=pow(A,-1,26)
        for B in ValuesofB:
            PlainText=""
            for char in CipherText:
                if char.isalpha():
                    if char.isupper():
                        PlainText+=chr(A_Inv * (ord(char)-B-ord('A')) % 26 + ord('A'))
                    else:
                        PlainText+=chr(A_Inv * (ord(char)-B-ord('a'))% 26 + ord('a'))
                        
                else:
                    PlainText+=char
                
            #calculating the frequency of common english words in each plaintext
            CommonWords=loadCommonWords()
            freq=sum(PlainText.count(words) for words in CommonWords)
            key=f"{A_Inv} {B}"
            FreqDic[key]=freq
        SortedFreqDic=dict(sorted(FreqDic.items(), key=lambda x: x[1], reverse=True))
    return SortedFreqDic     

def DecryptingTopCandidates(Top5):
    CipherText=Read("cipher2025.txt")
    DecrpytedText=""
    for index, pairs in enumerate(Top5):
        a_inv, b=map(int, pairs[0].split())
        #decrypting the cipher text with the top candidates a_inv and b values
        #formula: D(x)=a_inv*(y-b) mod 26
        for char in CipherText:
            if(char.isalpha()):
                if(char.isupper()):
                    DecrpytedText+=chr(a_inv * (ord(char)-b-ord('A')) % 26 + ord('A'))
                else:
                    DecrpytedText+=chr(a_inv * (ord(char)-b-ord('a')) % 26 + ord('a'))
            else:
                DecrpytedText+=char
        with open(f"Top{index+1} {pairs}.txt", "w") as file:
            file.write(DecrpytedText)              

def TopCandidates(SortedFreqDic):
    print(SortedFreqDic)  #proving that I have tried all the possible pairs of a and b
    print(len(SortedFreqDic))
    Top5=list(SortedFreqDic.items())[:5]
    DecryptingTopCandidates(Top5)
    
CipherText=Read("cipher2025.txt")
ValuesOfA=[1,3,5,7,9,11,15,17,19,21,23,25]   #coprime with m
ValuesOfB=list(range(26)) #b ranges from 0 to 25
Pair=pairing(ValuesOfA, ValuesOfB)
SortedFreqDic=Decrypting(ValuesOfA,ValuesOfB,CipherText)
TopCandidates(SortedFreqDic)