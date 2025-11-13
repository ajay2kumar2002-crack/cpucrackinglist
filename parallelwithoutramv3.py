import os
import time
import multiprocessing
import pyzipper  # pip install pyzipper
import queue
import itertools
import string
import math
import traceback
import zlib # Import zlib to catch its specific error

# --- FIX 5: Password Generator Architecture ---

class PasswordGenerator:
    """Base class for password generators."""
    def __iter__(self):
        return self

    def __next__(self):
        raise NotImplementedError("Subclasses must implement __next__")

    def __len__(self):
        """Return the total number of passwords to be generated."""
        raise NotImplementedError("Subclasses must implement __len__ for ETA calculation.")

class WordlistGenerator(PasswordGenerator):
    """Generates passwords from a wordlist file."""
    def __init__(self, wordlist_path, start_line=0):
        self.wordlist_path = wordlist_path
        self.start_line = start_line
        self._total_lines = None

    def __len__(self):
        if self._total_lines is None:
            print("Counting lines in wordlist...")
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                self._total_lines = sum(1 for _ in f)
        return self._total_lines - self.start_line

    def __iter__(self):
        self.f = open(self.wordlist_path, 'r', errors='ignore')
        # Skip to the start line
        for _ in range(self.start_line):
            next(self.f, None)
        return self

    def __next__(self):
        line = self.f.readline()
        if not line:
            self.f.close()
            raise StopIteration
        return line.strip()

class BruteForceGenerator(PasswordGenerator):
    """Generates passwords using brute-force (combinatorial) attack."""
    def __init__(self, charset, min_len, max_len):
        self.charset = charset
        self.min_len = min_len
        self.max_len = max_len
        self._length_generator = iter(range(self.min_len, self.max_len + 1))
        self._current_product_iterator = None
        self._total_combinations = self._calculate_total_combinations()
        self._is_large = self._check_if_large()

    def _check_if_large(self):
        """Check if the total number of combinations is too large to handle."""
        # If the number of combinations exceeds 10^15, consider it too large
        # This is a practical threshold to avoid overflow issues
        try:
            # Check if any single length calculation would be too large
            for length in range(self.min_len, self.max_len + 1):
                if len(self.charset) ** length > 10**15:
                    return True
            return False
        except OverflowError:
            return True

    def _calculate_total_combinations(self):
        try:
            total = 0
            for length in range(self.min_len, self.max_len + 1):
                total += len(self.charset) ** length
            return total
        except OverflowError:
            # Return a special value to indicate overflow
            return float('inf')

    def __len__(self):
        if self._is_large:
            return float('inf')
        return self._total_combinations

    def __iter__(self):
        self._length_generator = iter(range(self.min_len, self.max_len + 1))
        self._current_product_iterator = None
        return self

    def __next__(self):
        while True:
            if self._current_product_iterator is None:
                try:
                    current_length = next(self._length_generator)
                    self._current_product_iterator = itertools.product(self.charset, repeat=current_length)
                except StopIteration:
                    raise StopIteration # All lengths have been tried
            
            try:
                # Join the tuple of characters into a string
                return "".join(next(self._current_product_iterator))
            except StopIteration:
                # Move to the next length
                self._current_product_iterator = None

# --- End of FIX 5 ---


def get_file_path(prompt, file_type):
    """Prompt user for file path and validate it exists"""
    while True:
        path = input(prompt)
        if os.path.exists(path):
            return path
        print(f"Error: {file_type} file not found at that location. Please try again.")


# --- FINAL FIX: Robust Worker Function that ignores expected errors ---
def worker(zip_path, work_queue, result_queue, stop_event, progress_queue):
    """
    Generic worker that gets passwords from a queue and tests them.
    Opens the ZIP file ONCE per process for efficiency and stability.
    """
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            while not stop_event.is_set():
                try:
                    password = work_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                if password is None:
                    break

                try:
                    zf.pwd = password.encode('utf-8')
                    if zf.testzip() is None:
                        result_queue.put(password)
                        stop_event.set()
                        return
                # FINAL FIX: Catch and ignore the specific, expected errors for wrong passwords.
                except (RuntimeError, pyzipper.BadZipFile, zlib.error):
                    # These are expected when the password is wrong, so we just continue.
                    pass
                
                progress_queue.put(1)
    except Exception as e:
        # Catch any other TRULY unexpected error
        print(f"\n[CRITICAL ERROR] A worker process has crashed!")
        print(f"Error: {e}")
        traceback.print_exc()
        stop_event.set()


def feeder_process(password_generator, work_queue, stop_event):
    """
    Feeds passwords from the generator into the work queue.
    """
    try:
        for password in password_generator:
            if stop_event.is_set():
                break
            work_queue.put(password)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] The feeder process has crashed!")
        print(f"Error: {e}")
        traceback.print_exc()
        stop_event.set()
    finally:
        # Signal that feeding is complete by putting a 'None' sentinel
        for _ in range(multiprocessing.cpu_count()): # Ensure all workers get the signal
             work_queue.put(None)


def crack_zip(zip_path, password_generator, output_file='found_password.txt'):
    """
    Cracks a ZIP using a provided password generator.
    """
    start_time = time.time()
    
    # Handle large password spaces
    try:
        total_passwords = len(password_generator)
        # FIX: Check if the result is infinity
        if total_passwords == float('inf'):
            print("Warning: The password space is too large to calculate.")
            print("Progress percentage and ETA will not be available.")
            total_passwords = None
        else:
            print(f"Total passwords to try: {total_passwords}")
    except OverflowError:
        print("Warning: The password space is too large to calculate.")
        print("Progress percentage and ETA will not be available.")
        total_passwords = None
    except TypeError:
        # This handles the case where len() returns float('inf')
        print("Warning: The password space is too large to calculate.")
        print("Progress percentage and ETA will not be available.")
        total_passwords = None
    
    num_cores = max(1, multiprocessing.cpu_count() - 2)
    print(f"Starting parallel cracking with {num_cores} cores")
    
    # Create multiprocessing objects
    work_queue = multiprocessing.Queue(maxsize=num_cores * 100)
    result_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    
    # Start the feeder process
    feeder = multiprocessing.Process(
        target=feeder_process,
        args=(password_generator, work_queue, stop_event)
    )
    feeder.start()

    # Create and start worker processes
    processes = []
    for _ in range(num_cores):
        p = multiprocessing.Process(
            target=worker,
            args=(zip_path, work_queue, result_queue, stop_event, progress_queue)
        )
        processes.append(p)
        p.start()

    # --- Main process loop for monitoring and feedback ---
    total_tried = 0
    while not stop_event.is_set():
        try:
            attempts = progress_queue.get(timeout=0.5)
            total_tried += attempts
        except queue.Empty:
            pass

        current_time = time.time()
        elapsed_time = current_time - start_time
        
        if total_passwords is not None:
            progress_percent = (total_tried / total_passwords) * 100 if total_passwords > 0 else 0
            rate = total_tried / elapsed_time if elapsed_time > 0 else 0
            
            if rate > 0:
                eta_seconds = (total_passwords - total_tried) / rate
                eta = f"{int(eta_seconds // 60):02d}:{int(eta_seconds % 60):02d}"
            else:
                eta = "--:--"

            print(f"\rProgress: {total_tried}/{total_passwords} ({progress_percent:.2f}%) | "
                  f"Rate: {rate:.0f} p/s | ETA: {eta}", end="", flush=True)
        else:
            rate = total_tried / elapsed_time if elapsed_time > 0 else 0
            print(f"\rTried: {total_tried} passwords | Rate: {rate:.0f} p/s", end="", flush=True)

    # Stop all processes gracefully
    stop_event.set()
    feeder.join(timeout=1)
    for p in processes:
        p.join(timeout=1)

    print() # Newline after progress bar

    # Check result
    if not result_queue.empty():
        password = result_queue.get()
        duration = time.time() - start_time
        print(f"\n[SUCCESS] Password found: {password}")
        print(f"Time elapsed: {duration:.2f} seconds")
        
        with open(output_file, 'w') as f:
            f.write(password)
        print(f"Password saved to {output_file}")
        return True
    else:
        duration = time.time() - start_time
        print(f"\nPassword not found or an error occurred.")
        print(f"Time elapsed: {duration:.2f} seconds")
        return False

if __name__ == "__main__":
    # --- FIX: Added a main loop to handle 'continue' statements ---
    while True:
        print("=== Advanced Parallel ZIP Password Cracker ===")
        print("This tool supports dictionary and brute-force attacks.\n")
        
        zip_file = get_file_path("Enter the full path to your encrypted ZIP file: ", "ZIP")
        
        attack_type = input("Choose attack type (1 for Dictionary, 2 for Brute-Force, or 'q' to quit): ").strip()
        
        if attack_type.lower() == 'q':
            print("Exiting.")
            break
        
        if attack_type == '1':
            wordlist = get_file_path("Enter the full path to your password wordlist file: ", "wordlist")
            generator = WordlistGenerator(wordlist)
            crack_zip(zip_file, generator)
            
        elif attack_type == '2':
            print("\n--- Brute-Force Configuration ---")
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
            
            try:
                min_len = int(input("Enter minimum password length: "))
                max_len = int(input("Enter maximum password length: "))
            except ValueError:
                print("Invalid length. Please enter numbers only.")
                continue # Go back to the start of the loop
            
            # Calculate approximate combinations to warn user
            try:
                total_combinations = 0
                for length in range(min_len, max_len + 1):
                    total_combinations += len(charset) ** length
                
                if total_combinations > 10**12:
                    print(f"\nWARNING: This will try approximately {total_combinations:.2e} combinations.")
                    print("This could take an extremely long time or be practically impossible.")
                    confirm = input("Are you sure you want to continue? (y/n): ").strip().lower()
                    if confirm != 'y':
                        print("Brute-force attack cancelled.")
                        continue # Go back to the start of the loop
                else:
                    print(f"\nWARNING: A large character set or length range can result in an astronomically large number of combinations.")
                    confirm = input(f"Continue with charset ({len(charset)} chars) and length {min_len}-{max_len}? (y/n): ").strip().lower()
                    if confirm != 'y':
                        print("Brute-force attack cancelled.")
                        continue # Go back to the start of the loop
            except OverflowError:
                print(f"\nWARNING: The number of combinations is too large to calculate.")
                print("This could take an extremely long time or be practically impossible.")
                confirm = input("Are you sure you want to continue? (y/n): ").strip().lower()
                if confirm != 'y':
                    print("Brute-force attack cancelled.")
                    continue # Go back to the start of the loop
            
            generator = BruteForceGenerator(charset, min_len, max_len)
            crack_zip(zip_file, generator)
        else:
            print("Invalid choice. Please try again.")
            continue # Go back to the start of the loop

        # After a successful or failed crack attempt, ask if the user wants to try again
        another = input("\nDo you want to try another file or attack? (y/n): ").strip().lower()
        if another != 'y':
            print("Exiting.")
            break