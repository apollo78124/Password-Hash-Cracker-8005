import os

# Process Shadow File
def ReadShadowFile(filePath):

    if not os.path.exists(filePath):
        print(f"File at {filePath} doesn't exist")
        return None  # Process does not exist or does not have net/dev info

    try:
        with open(filePath, 'r') as file:
            lines = file.readlines()

        # Skip the first two lines (header)
        data = {}
        for line in lines[0:]:
            # Split the line into interface name and stats
            parts = line.split(':')
            if len(parts) > 2:
                userName = parts[0].strip()
                passwordHash = parts[1].strip()

                data[userName] = {
                    "password_hash": passwordHash
                }

        return data

    except Exception as e:
        print(f"Error reading file at {filePath}: {e}")
        return None