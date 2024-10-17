from ReadShadowFile import ReadShadowFile
from Sha512Solver import ReturnPasswordFromSha512Hash
from yescryptsolver import ReturnPasswordFromYesCryptHash
import time

#Sample file password: "b", "bc", "abb", "abba"
print("Password Hash Crack")
username = input('Enter UserName:\n')
filePath1 = input('Enter shadow file location: \n')


# Start time
start_time = time.time()

if len(filePath1) < 1:
    fileLocation = "./etc.shadow.sample.txt"
else:
    fileLocation = filePath1

shadowFile = ReadShadowFile(fileLocation)

userInterest = shadowFile[username]
passwordHash = userInterest["password_hash"].split("$")
crackedPassword = ""

if len(passwordHash) == 4 :
    #MD5
    if passwordHash[1] == "1":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("MD5 Password Crack Result: " + crackedPassword)
    #Blowfish
    if passwordHash[1] == "2b":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("Blowfish Password Crack Result: " + crackedPassword)
    #Blowfish
    if passwordHash[1] == "2y":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("Blowfish Password Crack Result: " + crackedPassword)
    #SHA-256
    if passwordHash[1] == "5":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("SHA-256 Password Crack Result: " + crackedPassword)
    #SHA-512
    if passwordHash[1] == "6":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("SHA-512 Password Crack Result: " + crackedPassword)
if len(passwordHash) == 5 :
    #yescrypt
    if passwordHash[1] == "y":
        crackedPassword = ReturnPasswordFromYesCryptHash(passwordHash)
        print("Yescrypt Password Crack Result: " + crackedPassword)
# End time
end_time = time.time()

# Calculate execution time
execution_time = end_time - start_time
print(f"Execution Time: {execution_time:.6f} seconds")


