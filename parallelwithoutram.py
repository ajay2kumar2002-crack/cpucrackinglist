import os
import time
import multiprocessing
import pyzipper  # pip install pyzipper

def get_file_path(prompt, file_type):
    """Prompt user for file path and validate it exists"""
    while True:
        path = input(prompt)
        if os.path.exists(path):
            return path
        print(f"Error: {file_type} file not found at that location. Please try again.")

def verify_password(zip_path, password):
    """
    Verify a password by attempting to read the first file in the ZIP.
    Returns True if password is correct, False otherwise.
    """
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.pwd = password.encode('utf-8')
            file_list = zf.namelist()
            if not file_list:
                return False  # Empty ZIP
            # Try to read the first file in memory
            first_file = file_list[0]
            zf.read(first_file)
            return True
    except (RuntimeError, pyzipper.BadZipFile, Exception):
        return False

def worker_chunk(zip_path, start_line, end_line, wordlist_path, result_queue, stop_event, progress_file):
    """
    Worker function that processes a chunk of lines from the wordlist.
    """
    with open(wordlist_path, 'r', errors='ignore') as f:
        # Skip to start_line
        for _ in range(start_line):
            if stop_event.is_set():
                return
            next(f)
        
        # Process lines from start_line to end_line
        for line_num in range(start_line, end_line):
            if stop_event.is_set():
                return
                
            line = f.readline()
            if not line:
                break
                
            password = line.strip()
            
            # Verify password
            if verify_password(zip_path, password):
                result_queue.put(password)
                stop_event.set()
                return
            
            # Update progress file every 100 attempts
            if line_num % 100 == 0:
                with open(progress_file, 'w') as pf:
                    pf.write(str(line_num))

def crack_zip_parallel_chunked(zip_path, wordlist_path, output_file='found_password.txt', progress_file='progress.txt'):
    """
    Parallel password cracking using all CPU cores without loading entire wordlist.
    """
    start_time = time.time()
    
    # Count total lines in wordlist
    print("Counting lines in wordlist...")
    with open(wordlist_path, 'r', errors='ignore') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"Total passwords to try: {total_lines}")
    
    # Check for existing progress
    start_line = 0
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as pf:
            try:
                start_line = int(pf.read().strip())
                print(f"Resuming from line {start_line}")
            except:
                start_line = 0
    
    num_cores = multiprocessing.cpu_count() -2  # Leave some cores free
    lines_per_core = (total_lines - start_line) // num_cores
    
    print(f"Starting parallel cracking with {num_cores} cores")
    print(f"Lines per core: {lines_per_core}")
    
    # Create multiprocessing objects
    result_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    
    # Create and start worker processes
    processes = []
    for i in range(num_cores):
        core_start = start_line + i * lines_per_core
        core_end = core_start + lines_per_core
        if i == num_cores - 1:  # Last core takes remaining lines
            core_end = total_lines
        
        p = multiprocessing.Process(
            target=worker_chunk,
            args=(zip_path, core_start, core_end, wordlist_path, result_queue, stop_event, progress_file)
        )
        processes.append(p)
        p.start()
    
    # Wait for all processes to complete
    for p in processes:
        p.join()
    
    # Check if password was found
    if not result_queue.empty():
        password = result_queue.get()
        duration = time.time() - start_time
        print(f"\n[SUCCESS] Password found: {password}")
        print(f"Time elapsed: {duration:.2f} seconds")
        
        with open(output_file, 'w') as f:
            f.write(password)
        print(f"Password saved to {output_file}")
        
        # Clean up progress file
        if os.path.exists(progress_file):
            os.remove(progress_file)
        return True
    else:
        duration = time.time() - start_time
        print(f"\nPassword not found in wordlist.")
        print(f"Time elapsed: {duration:.2f} seconds")
        return False

if __name__ == "__main__":
    print("=== Memory-Efficient Parallel ZIP Password Cracker ===")
    print("This tool uses all CPU cores without loading the entire wordlist into memory.\n")
    
    # Get file paths from user
    zip_file = get_file_path("Enter the full path to your encrypted ZIP file: ", "ZIP")
    wordlist = get_file_path("Enter the full path to your password wordlist file: ", "wordlist")
    
    # Run the parallel cracker
    crack_zip_parallel_chunked(zip_file, wordlist)
