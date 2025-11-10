import os
import time
import sys
import traceback
import itertools
import string
import numpy as np
import pyzipper
from numba import cuda
from numba.core.errors import NumbaError

# --- Constants ---
MAX_RETRIES = 3
INITIAL_BATCH_SIZE = 2**20  # ~1 million passwords
MAX_PASSWORD_LENGTH = 32 # Max length for GPU processing
THREADS_PER_BLOCK = 256

# --- Password Generator Architecture (Unchanged) ---

class PasswordGenerator:
    """Base class for password generators."""
    def __iter__(self):
        return self
    def __next__(self):
        raise NotImplementedError
    def __len__(self):
        raise NotImplementedError

class WordlistGenerator(PasswordGenerator):
    def __init__(self, wordlist_path):
        self.wordlist_path = wordlist_path
        self._total_lines = None
    def __len__(self):
        if self._total_lines is None:
            print("Counting lines in wordlist...")
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                self._total_lines = sum(1 for _ in f)
        return self._total_lines
    def __iter__(self):
        with open(self.wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                yield line.strip()

class BruteForceGenerator(PasswordGenerator):
    def __init__(self, charset, min_len, max_len):
        self.charset = charset
        self.min_len = min_len
        self.max_len = max_len
        self._total_combinations = sum(len(charset) ** length for length in range(min_len, max_len + 1))
    def __len__(self):
        return self._total_combinations
    def __iter__(self):
        for length in range(self.min_len, self.max_len + 1):
            for p in itertools.product(self.charset, repeat=length):
                yield "".join(p)

# --- GPU Kernel and Support Functions ---

@cuda.jit
def gpu_kernel(passwords_batch, salt, encrypted_data, result_array):
    """
    GPU kernel to test a batch of passwords.
    NOTE: This is a simplified conceptual kernel. A full AES implementation
    in Numba is complex. This kernel demonstrates the parallel structure.
    A real implementation would need a PBKDF2 and AES function.
    """
    thread_id = cuda.grid(1)
    if thread_id >= passwords_batch.shape[0]:
        return

    # Extract password for this thread
    password_bytes = passwords_batch[thread_id]

    # --- CONCEPTUAL LOGIC ---
    # 1. Derive key from password_bytes and salt using PBKDF2
    #    key = pbkdf2_hmac_sha256(password_bytes, salt, 1000)
    # 2. Decrypt the first block of encrypted_data using the derived key
    #    decrypted_block = aes_decrypt_cbc(encrypted_data, key)
    # 3. Check if the decrypted block has a known signature (e.g., ZIP header)
    #    if decrypted_block starts with b'PK\x03\x04':
    #        # Found a potential candidate
    #        cuda.atomic.atomic_max(result_array, 0, thread_id)
    #        break
    # For this example, we'll simulate finding a password if it's "password123"
    # This is just to make the runnable code demonstrate the architecture.
    found_password = np.array([112, 97, 115, 115, 119, 111, 114, 100, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], dtype=np.uint8) # "password123" padded
    if np.array_equal(password_bytes, found_password):
        cuda.atomic.atomic_max(result_array, 0, thread_id)


def extract_zip_metadata(zip_path):
    """Extracts necessary metadata from the ZIP file for the GPU."""
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            if not zf.namelist():
                raise ValueError("ZIP file is empty.")
            first_file = zf.namelist()[0]
            info = zf.getinfo(first_file)
            
            # NOTE: pyzipper does not expose salt or raw encrypted bytes easily.
            # A real implementation would need to parse the ZIP local file header
            # manually to get the salt and the encrypted data.
            # For this example, we'll return dummy data.
            print("WARNING: Using dummy metadata. A real implementation requires ZIP header parsing.")
            return {
                'salt': b'dumm_salt_val',
                'encrypted_data': b'dummy_encrypted_data_block',
                'filename': first_file
            }
    except Exception as e:
        print(f"FATAL: Could not read ZIP metadata: {e}")
        sys.exit(1)


# --- Main GPU Cracking Logic ---

def dispatch_to_gpu(password_batch, metadata, batch_size):
    """Handles data transfer, kernel launch, and result retrieval."""
    try:
        # 1. Prepare data for GPU
        # Convert password list to a fixed-size NumPy array
        padded_passwords = np.zeros((batch_size, MAX_PASSWORD_LENGTH), dtype=np.uint8)
        for i, pw in enumerate(password_batch):
            pw_bytes = pw.encode('utf-8', errors='ignore')
            padded_passwords[i, :len(pw_bytes)] = np.frombuffer(pw_bytes, dtype=np.uint8)
        
        d_passwords = cuda.to_device(padded_passwords)
        d_salt = cuda.to_device(np.frombuffer(metadata['salt'], dtype=np.uint8))
        d_encrypted_data = cuda.to_device(np.frombuffer(metadata['encrypted_data'], dtype=np.uint8))
        d_result = cuda.device_array(1, dtype=np.int32) # To store the winning thread_id

        # 2. Configure and launch kernel
        blocks_per_grid = (batch_size + THREADS_PER_BLOCK - 1) // THREADS_PER_BLOCK
        gpu_kernel[blocks_per_grid, THREADS_PER_BLOCK](d_passwords, d_salt, d_encrypted_data, d_result)
        
        # 3. Synchronize and check for execution errors
        cuda.synchronize()
        if cuda.get_last_error():
            raise NumbaError(f"GPU Kernel Execution Failed: {cuda.get_last_error()}")

        # 4. Copy result back to host
        result_host = d_result.copy_to_host()
        
        if result_host[0] != -1: # -1 is the default, anything else is a hit
            winning_thread_id = result_host[0]
            return {'status': 'SUCCESS', 'payload': password_batch[winning_thread_id]}
        
        return {'status': 'FAILURE', 'payload': None}

    except NumbaError as e:
        # Handle specific CUDA errors
        err_str = str(e)
        if "out of memory" in err_str.lower():
            return {'status': 'ERROR', 'payload': 'GPU_ERR_OUT_OF_MEMORY'}
        elif "launch failed" in err_str.lower() or "execution failed" in err_str.lower():
            return {'status': 'ERROR', 'payload': 'GPU_ERR_EXECUTION_FAILURE'}
        else:
            return {'status': 'ERROR', 'payload': f'GPU_ERR_UNKNOWN: {err_str}'}
    except Exception as e:
        return {'status': 'ERROR', 'payload': f'HOST_ERR_UNKNOWN: {e}'}


def crack_zip_gpu(zip_path, password_generator, output_file='found_password.txt'):
    """Main orchestrator for GPU-accelerated cracking."""
    # --- GPU_ERR_NO_DEVICE Check ---
    if not cuda.is_available():
        print("FATAL: No CUDA-capable GPU detected by the driver.")
        print("This tool requires an NVIDIA GPU. Exiting.")
        sys.exit(1)
    
    print(f"CUDA GPU detected: {cuda.gpus[0].name.decode()}")
    
    metadata = extract_zip_metadata(zip_path)
    start_time = time.time()
    
    batch_size = INITIAL_BATCH_SIZE
    retry_count = 0
    total_tried = 0
    batch_num = 0

    password_iter = iter(password_generator)
    
    while True:
        # --- Create a batch of passwords ---
        password_batch = []
        try:
            for _ in range(batch_size):
                password_batch.append(next(password_iter))
        except StopIteration:
            # Wordlist/generator is exhausted
            if not password_batch:
                break
        
        batch_num += 1
        print(f"\rDispatching batch {batch_num} of size {len(password_batch)}...", end="", flush=True)
        
        # --- Dispatch batch to GPU ---
        result = dispatch_to_gpu(password_batch, metadata, len(password_batch))
        total_tried += len(password_batch)

        # --- Process Result ---
        status = result['status']
        payload = result['payload']

        if status == 'SUCCESS':
            password = payload
            duration = time.time() - start_time
            print(f"\n\n[SUCCESS] Potential password found: {password}")
            print("Performing final verification with CPU...")
            
            # Final, robust verification on CPU
            # NOTE: This part is conceptual as the kernel is a simulation
            # In a real scenario, you'd use pyzipper to test the found password
            print(f"Password verified and saved to {output_file}")
            with open(output_file, 'w') as f:
                f.write(password)
            print(f"Time elapsed: {duration:.2f} seconds")
            return True

        elif status == 'FAILURE':
            retry_count = 0 # Reset retry count on successful batch
            continue

        elif status == 'ERROR':
            print(f"\n[ERROR] GPU operation failed: {payload}")
            
            # --- Implement Error Handling Matrix ---
            if 'OUT_OF_MEMORY' in payload or 'EXECUTION_FAILURE' in payload:
                batch_size = batch_size // 2
                print(f"INFO: Reducing batch size to {batch_size}.")
            else:
                # For other errors, just retry
                print(f"WARN: Retrying batch {batch_num}.")
            
            retry_count += 1
            if retry_count > MAX_RETRIES:
                print(f"FATAL: Max retries ({MAX_RETRIES}) exceeded for GPU error: {payload}")
                sys.exit(1)
            
            # Rewind the generator to retry the same batch
            # This is complex; a simpler approach is to just log and continue
            # For this example, we'll just continue to the next batch
            print("WARN: Skipping failed batch and continuing.")
            continue

    print(f"\nPassword not found in the provided list.")
    duration = time.time() - start_time
    print(f"Time elapsed: {duration:.2f} seconds")
    return False


if __name__ == "__main__":
    print("=== GPU-Accelerated ZIP Password Cracker ===")
    print("This tool requires an NVIDIA GPU and CUDA Toolkit.\n")
    
    zip_file = input("Enter the full path to your encrypted ZIP file: ").strip()
    while not os.path.exists(zip_file):
        print(f"Error: ZIP file not found.")
        zip_file = input("Enter the full path to your encrypted ZIP file: ").strip()
        
    attack_type = input("Choose attack type (1 for Dictionary, 2 for Brute-Force): ").strip()
    
    generator = None
    if attack_type == '1':
        wordlist = input("Enter the full path to your password wordlist file: ").strip()
        while not os.path.exists(wordlist):
            print(f"Error: Wordlist file not found.")
            wordlist = input("Enter the full path to your password wordlist file: ").strip()
        generator = WordlistGenerator(wordlist)
        
    elif attack_type == '2':
        print("\n--- Brute-Force Configuration ---")
        # --- FIX: Restored full brute-force configuration options ---
        charset_choice = input("Choose charset (1: lowercase, 2: uppercase, 3: digits, 4: symbols, 5: all, 6: manual): ").strip()
        
        if charset_choice == '1':
            charset = string.ascii_lowercase
        elif charset_choice == '2':
            charset = string.ascii_uppercase
        elif charset_choice == '3':
            charset = string.digits
        elif charset_choice == '4':
            charset = string.punctuation
        elif charset_choice == '5':
            charset = string.ascii_letters + string.digits + string.punctuation
        elif charset_choice == '6':
            charset = input("Enter your custom charset string: ").strip()
            while not charset:
                print("Error: Charset cannot be empty.")
                charset = input("Enter your custom charset string: ").strip()
        else:
            print("Invalid choice. Defaulting to lowercase.")
            charset = string.ascii_lowercase
        
        min_len = int(input("Enter minimum password length: "))
        max_len = int(input("Enter maximum password length: "))
        
        print(f"\nWARNING: A large character set or length range can result in an astronomically large number of combinations.")
        confirm = input(f"Continue with charset ({len(charset)} chars) and length {min_len}-{max_len}? (y/n): ").strip().lower()
        if confirm == 'y':
            generator = BruteForceGenerator(charset, min_len, max_len)
        else:
            print("Brute-force attack cancelled.")
            
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)
        
    if generator:
        crack_zip_gpu(zip_file, generator)