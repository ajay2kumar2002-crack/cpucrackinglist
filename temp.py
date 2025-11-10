import pyzipper
import sys

zip_path = "your_file.zip" # Change this to your file's path

try:
    with pyzipper.AESZipFile(zip_path) as zf:
        # Check if the is_encrypted attribute exists and is True
        if hasattr(zf, 'is_encrypted') and zf.is_encrypted:
            # Check if it's an AESZipFile instance, which implies AES
            if isinstance(zf, pyzipper.AESZipFile):
                print(f"'{zip_path}' is encrypted with WinZip AES.")
            else:
                print(f"'{zip_path}' is encrypted, but likely with the older, insecure ZipCrypto standard.")
        else:
            print(f"'{zip_path}' is not encrypted.")
except (RuntimeError, pyzipper.BadZipFile) as e:
    print(f"Could not open '{zip_path}' or it's not a valid ZIP file.")
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
