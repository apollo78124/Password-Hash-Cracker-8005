from ReadShadowFile import ReadShadowFile
from Sha512Solver import ReturnPasswordFromSha512Hash

shadowFile = ReadShadowFile("./etc.shadow.sample.txt")

userInterest = shadowFile["paulanka"]
passwordHash = userInterest["password_hash"].split("$")
crackedPassword = ""

if len(passwordHash) == 4 :
    #SHA-512
    if passwordHash[1] == "6":
        crackedPassword = ReturnPasswordFromSha512Hash(passwordHash)
        print("SHA-512 Password Crack Result: " + crackedPassword)


