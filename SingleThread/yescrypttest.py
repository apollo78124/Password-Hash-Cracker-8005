import crypt
import os
#$y$j9T$VPr6lkbga49CwlqxXUabB0$iw6v.5AXTeT3WLs3IAP9/RN5njZqzizWFo9d3t1qax7
#password: ab
from passlib.hash import yescrypt

# Input string and salt
input_string = "ab"
custom_salt = "VPr6lkbga49CwlqxXUabB0"

# Hash the string
hashed_value = yescrypt.using(salt=custom_salt).hash(input_string)

# Print the hashed value
print(f"Hashed Value: {hashed_value}")
