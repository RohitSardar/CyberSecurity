import os, hashlib


def calculate_file_hash(filename):
    sha256_hash = hashlib.sha256()
    with open (filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_integrity():
    current_directory = os.getcwd()
    for root, _, files in os.walk(current_directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path + ".hash", "r") as f:
                    stored_hash = f.read()
            except FileNotFoundError:
                print(f"No stored hash found for '{file_path}'. Generating and storing hash...")
                hash_value = calculate_file_hash(file_path)
                with open(file_path + ".hash", "w") as f:
                    f.write(hash_value)
                print("Hash value stored.")
                continue

            current_hash = calculate_file_hash(file_path)
            if stored_hash == current_hash:
                print(f"File integrity intact for '{file_path}'. The file has not been modified.")
            else:
                print(f"File integrity compromised for '{file_path}'. The file has been modified.")
                print(f"Stored hash: {stored_hash}")
                print(f"Current hash: {current_hash}")


if __name__ == "__main__":
    check_integrity()