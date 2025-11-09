import os
import time
import multiprocessing
import pyzipper  # pip install pyzipper
import queue # Import queue for the Empty exception

def get_file_path(prompt, file_type):
    """Prompt user for file path and validate it exists"""
    while True:
        path = input(prompt)
        if os.path.exists(path):
            return path
        print(f"Error: {file_type} file not found at that location. Please try again.")

# FIX 4: Improved password verification to prevent false negatives.
def verify_password(zip_path, password):
    """
    Verify a password by testing the integrity of all files in the ZIP.
    Returns True if password is correct, False otherwise.
    """
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.pwd = password.encode('utf-8')
            # testzip() returns None if all files are correct, 
            # or the name of the first bad file otherwise.
            if zf.testzip() is None:
                return True
            else:
                return False
    except (RuntimeError, pyzipper.BadZipFile, Exception):
        return False

def worker_chunk(zip_path, start_line, end_line, wordlist_path, result_queue, stop_event, progress_queue):
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
        attempts_in_chunk = 0
        for line_num in range(start_line, end_line):
            if stop_event.is_set():
                return
                
            line = f.readline()
            if not line:
                break
                
            password = line.strip()
            attempts_in_chunk += 1
            
            # Verify password
            if verify_password(zip_path, password):
                result_queue.put(password)
                stop_event.set()
                return
            
            # FIX 1: Report progress to a queue instead of writing to a file.
            # This avoids race conditions. We report every 100 attempts.
            if attempts_in_chunk % 100 == 0:
                progress_queue.put(100)
                attempts_in_chunk = 0

def crack_zip_parallel_chunked(zip_path, wordlist_path, output_file='found_password.txt', progress_file='progress.txt'):
    """
    Parallel password cracking using all CPU cores without loading entire wordlist.
    Includes robust progress reporting and real-time feedback.
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
        try:
            with open(progress_file, 'r') as pf:
                start_line = int(pf.read().strip())
                print(f"Resuming from line {start_line}")
        except (IOError, ValueError):
            start_line = 0
    
    num_cores = max(1, multiprocessing.cpu_count() - 2) # Ensure at least 1 core
    lines_per_core = (total_lines - start_line) // num_cores
    
    print(f"Starting parallel cracking with {num_cores} cores")
    print(f"Lines per core: {lines_per_core}")
    
    # Create multiprocessing objects
    result_queue = multiprocessing.Queue()
    # FIX 1: Add a dedicated queue for progress updates.
    progress_queue = multiprocessing.Queue()
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
            # FIX 1: Pass the new progress_queue to workers.
            args=(zip_path, core_start, core_end, wordlist_path, result_queue, stop_event, progress_queue)
        )
        processes.append(p)
        p.start()

    # --- FIX 1, 3: Main process loop for monitoring, feedback, and file writing ---
    total_tried = start_line
    last_report_time = time.time()
    
    while not stop_event.is_set() and any(p.is_alive() for p in processes):
        try:
            # Get progress from workers with a short timeout
            attempts = progress_queue.get(timeout=0.5)
            total_tried += attempts
        except queue.Empty:
            # Timeout is expected, allows loop to check stop_event and process status
            pass

        # FIX 3: Real-time feedback to the console
        current_time = time.time()
        elapsed_time = current_time - start_time
        progress_percent = (total_tried / total_lines) * 100
        rate = (total_tried - start_line) / elapsed_time if elapsed_time > 0 else 0
        
        if rate > 0:
            eta_seconds = (total_lines - total_tried) / rate
            eta = f"{int(eta_seconds // 60):02d}:{int(eta_seconds % 60):02d}"
        else:
            eta = "--:--"

        print(f"\rProgress: {total_tried}/{total_lines} ({progress_percent:.2f}%) | "
              f"Rate: {rate:.0f} p/s | ETA: {eta}", end="", flush=True)
              
        # Simple, direct progress file writing (less robust to crashes)
        if current_time - last_report_time > 5: # Update file every 5 seconds
            with open(progress_file, 'w') as pf:
                pf.write(str(total_tried))
            last_report_time = current_time

    # Wait for all processes to complete
    for p in processes:
        p.join()

    # FIX 3: Print a newline to move past the progress bar
    print()

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
    print("=== Improved Memory-Efficient Parallel ZIP Password Cracker ===")
    print("This tool uses all CPU cores and provides real-time feedback.\n")
    
    # Get file paths from user
    zip_file = get_file_path("Enter the full path to your encrypted ZIP file: ", "ZIP")
    wordlist = get_file_path("Enter the full path to your password wordlist file: ", "wordlist")
    
    # Run the parallel cracker
    crack_zip_parallel_chunked(zip_file, wordlist)