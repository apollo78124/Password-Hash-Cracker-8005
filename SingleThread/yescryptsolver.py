import base64
import crypt
import itertools


# Solve Yescrypt Password
def ReturnPasswordFromYesCryptHash(passwordHash):
    # Extract the salt and hashed password from the hash_line
    # Example hash_line format: '$6$salt$hashed_password'
    parts = passwordHash
    if len(parts) < 4:
        print("Invalid hash format")
        return None

    algorithm = parts[1]  # 'y' indicates Yescrypt
    salt = parts[2]  # Extract the salt
    true_hash = parts[3]  # Extract the actual hashed password

    # Define a character set (for example, lowercase letters)
    char_set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'

    # Loop through all possible 1-character passwords
    for length in range(1, 5):
        for combo in itertools.product(char_set, repeat=length):
            # Join the tuple into a string
            passwordTemp = ''.join(combo)
            # Hash the current character using SHA-512 with the extracted salt
            test_hash = crypt.crypt(passwordTemp, f'${algorithm}${salt}$')
            print("Trying password: " + passwordTemp)
            # Compare the result to the original hash
            if test_hash.split('$')[3] == true_hash:
                print(f"Password found: {passwordTemp}")
                return passwordTemp

    return "Password crack failed"