import itertools
import datetime
import math
import os
import sys
import json
import time
import traceback
import io
import multiprocessing as mp
from multiprocessing import Pool, Manager, Lock

# --- EASY CONFIGURATION ---
CONFIG = {
    # 1. Names and common words to be used
    "names": ["vineet", "nidhi"],
    "common_words": ["sex", "drunk"],
    
    # 2. Date range for generation
    "start_date": {"day": 1, "month": 1, "year": 2025},
    "end_date": {"day": 28, "month": 2, "year": 2025},
    
    # 3. Combination rules
    "max_words_in_password": 4,
    
    # 4. Separators
    "separators_between_words": ["", " ", "_"],
    "separators_between_word_and_date": ["", " "],
    
    # 5. Performance settings
    "num_processes": None,  # None = use all CPU cores, or specify a number
    "buffer_memory_mb": 10,  # Buffer size per process in MB
    "max_capitalizations": 65536,  # 2^16 - reasonable limit
    "progress_update_interval": 5,  # Update progress every N seconds
}
# --- END OF CONFIGURATION ---


def date_generator(config, start_index=0):
    """Generate dates with proper skipping."""
    start_date = datetime.date(
        config['start_date']['year'], 
        config['start_date']['month'], 
        config['start_date']['day']
    )
    end_date = datetime.date(
        config['end_date']['year'], 
        config['end_date']['month'], 
        config['end_date']['day']
    )
    
    date_formats = ["%d-%m-%Y", "%d-%m-%y", "%d/%m/%Y", "%d/%m/%y"]
    
    # Calculate skip position
    days_to_skip = start_index // len(date_formats)
    formats_to_skip = start_index % len(date_formats)
    
    # Start at the correct date
    current_date = start_date + datetime.timedelta(days=days_to_skip)
    
    # First day: only yield remaining formats
    if current_date <= end_date and formats_to_skip > 0:
        for fmt in date_formats[formats_to_skip:]:
            yield current_date.strftime(fmt)
        current_date += datetime.timedelta(days=1)
    
    # Subsequent days: yield all formats
    while current_date <= end_date:
        for fmt in date_formats:
            yield current_date.strftime(fmt)
        current_date += datetime.timedelta(days=1)


def generate_capitalizations(s, max_caps, start_index=0):
    """Generate capitalizations with proper limit and deterministic sampling."""
    n = len(s)
    theoretical_combinations = 2 ** n
    
    # If within limit, generate all
    if theoretical_combinations <= max_caps:
        for i in range(start_index, theoretical_combinations):
            result = []
            for j in range(n):
                if (i >> j) & 1:
                    result.append(s[j].upper())
                else:
                    result.append(s[j].lower())
            yield "".join(result)
    else:
        # Limited mode: use deterministic sampling
        step = max(1, theoretical_combinations // max_caps)
        
        for i in range(start_index, max_caps):
            actual_index = i * step
            result = []
            for j in range(n):
                if (actual_index >> j) & 1:
                    result.append(s[j].upper())
                else:
                    result.append(s[j].lower())
            yield "".join(result)


def worker_process(task_queue, result_queue, config, process_id):
    """Worker process that generates passwords for assigned tasks."""
    buffer_size_bytes = config['buffer_memory_mb'] * 1024 * 1024
    base_words = config['names'] + config['common_words']
    
    while True:
        task = task_queue.get()
        if task is None:  # Poison pill
            break
        
        word_count, word_combo_indices = task
        buffer = io.StringIO()
        local_count = 0
        
        try:
            # Generate permutations for this word count
            all_perms = list(itertools.permutations(base_words, word_count))
            
            # Process only assigned indices
            for word_combo_index in word_combo_indices:
                if word_combo_index >= len(all_perms):
                    continue
                    
                word_tuple = all_perms[word_combo_index]
                
                # Iterate through all separators
                for sep in config['separators_between_words']:
                    word_part = sep.join(word_tuple)
                    
                    # Generate all dates
                    for date_str in date_generator(config):
                        # Append dates with each separator
                        for date_sep in config['separators_between_word_and_date']:
                            base_password = f"{word_part}{date_sep}{date_str}"
                            
                            # Generate all capitalizations
                            for capitalized_pass in generate_capitalizations(
                                base_password, 
                                config['max_capitalizations']
                            ):
                                buffer.write(capitalized_pass + '\n')
                                local_count += 1
                                
                                # Flush buffer if full
                                if buffer.tell() >= buffer_size_bytes:
                                    result_queue.put((process_id, buffer.getvalue(), local_count))
                                    buffer.seek(0)
                                    buffer.truncate(0)
                                    local_count = 0
            
            # Flush remaining buffer
            if buffer.tell() > 0:
                result_queue.put((process_id, buffer.getvalue(), local_count))
                
        except Exception as e:
            result_queue.put((process_id, f"ERROR: {e}", 0))


def writer_process(result_queue, output_path, total_passwords_shared, stop_event):
    """Writer process that collects results and writes to file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        while not stop_event.is_set() or not result_queue.empty():
            try:
                process_id, data, count = result_queue.get(timeout=0.1)
                
                if data.startswith("ERROR:"):
                    print(f"\n{data}")
                    continue
                
                f.write(data)
                total_passwords_shared.value += count
                
            except:
                continue


class MultiProcessWordlistGenerator:
    def __init__(self, config):
        self.config = config
        self.base_words = config['names'] + config['common_words']
        self.output_file = None
        
        # Determine number of processes
        if config['num_processes'] is None:
            self.num_processes = mp.cpu_count()
        else:
            self.num_processes = min(config['num_processes'], mp.cpu_count())
            
    def validate_config(self):
        """Validate configuration values."""
        if not self.base_words:
            raise ValueError("Both names and common_words lists cannot be empty.")
            
        if self.config['max_words_in_password'] < 1 or self.config['max_words_in_password'] > len(self.base_words):
            raise ValueError(f"max_words_in_password must be between 1 and {len(self.base_words)}.")
            
        start_date = datetime.date(
            self.config['start_date']['year'], 
            self.config['start_date']['month'], 
            self.config['start_date']['day']
        )
        end_date = datetime.date(
            self.config['end_date']['year'], 
            self.config['end_date']['month'], 
            self.config['end_date']['day']
        )
        
        if start_date > end_date:
            raise ValueError("start_date must be before or equal to end_date.")
            
        if (end_date - start_date).days > 365 * 10:
            print("WARNING: Date range is more than 10 years. This will generate a very large wordlist.")
            
        return True
        
    def estimate_file_size(self):
        """Estimate the file size by simulating the actual generation logic."""
        start_date = datetime.date(
            self.config['start_date']['year'], 
            self.config['start_date']['month'], 
            self.config['start_date']['day']
        )
        end_date = datetime.date(
            self.config['end_date']['year'], 
            self.config['end_date']['month'], 
            self.config['end_date']['day']
        )
        
        num_dates = (end_date - start_date).days + 1
        total_dates = num_dates * 4  # 4 date formats
        
        num_words = len(self.base_words)
        max_words = self.config['max_words_in_password']
        
        total_combinations = 0
        total_chars = 0
        
        for word_count in range(1, max_words + 1):
            # Number of permutations for this word count
            perms = math.perm(num_words, word_count)
            num_word_seps = len(self.config['separators_between_words'])
            num_date_seps = len(self.config['separators_between_word_and_date'])
            
            # For each permutation, calculate capitalizations based on ACTUAL string length
            # We need to check a sample to get accurate capitalization count
            sample_perm = list(itertools.islice(itertools.permutations(self.base_words, word_count), 1))[0]
            
            # For each word separator
            for word_sep in self.config['separators_between_words']:
                word_part = word_sep.join(sample_perm)
                
                # For each date separator (use a sample date)
                for date_sep in self.config['separators_between_word_and_date']:
                    sample_date = "01-01-2024"  # Sample date for length calculation
                    base_password = f"{word_part}{date_sep}{sample_date}"
                    
                    # Calculate actual capitalization count for this base password
                    n = len(base_password)
                    theoretical_caps = 2 ** n
                    actual_caps = min(theoretical_caps, self.config['max_capitalizations'])
                    
                    # Total for this combination
                    combinations_for_this_config = perms * total_dates * actual_caps
                    total_combinations += combinations_for_this_config
                    
                    # Estimate character count
                    avg_password_len = len(base_password)
                    total_chars += combinations_for_this_config * (avg_password_len + 1)  # +1 for newline
        
        # Estimate size
        estimated_size_bytes = total_chars
        estimated_size_gb = estimated_size_bytes / (1024**3)
        
        return int(total_combinations), estimated_size_gb
    
    def create_task_distribution(self):
        """Distribute work across processes."""
        tasks = []
        
        for word_count in range(1, self.config['max_words_in_password'] + 1):
            # Calculate total permutations for this word count
            total_perms = math.perm(len(self.base_words), word_count)
            
            # Distribute permutations across processes
            perms_per_process = max(1, total_perms // self.num_processes)
            
            for proc_id in range(self.num_processes):
                start_idx = proc_id * perms_per_process
                end_idx = start_idx + perms_per_process
                
                # Last process takes any remaining
                if proc_id == self.num_processes - 1:
                    end_idx = total_perms
                
                if start_idx < total_perms:
                    indices = list(range(start_idx, min(end_idx, total_perms)))
                    if indices:
                        tasks.append((word_count, indices))
        
        return tasks
        
    def generate_wordlist(self, output_path):
        """Generate the wordlist using multiple processes."""
        self.output_file = output_path
        
        print(f"Generating wordlist using {self.num_processes} processes...")
        print(f"Saving to: {output_path}")
        print("Note: This script does NOT remove duplicates. Use deduplicate_wordlist.py afterwards.")
        
        start_time = time.time()
        
        # Create shared counter and queues
        manager = Manager()
        task_queue = manager.Queue()
        result_queue = manager.Queue()
        total_passwords = manager.Value('i', 0)
        stop_event = manager.Event()
        
        # Create task distribution
        tasks = self.create_task_distribution()
        print(f"Created {len(tasks)} tasks distributed across {self.num_processes} processes")
        
        # Add tasks to queue
        for task in tasks:
            task_queue.put(task)
        
        # Add poison pills for workers
        for _ in range(self.num_processes):
            task_queue.put(None)
        
        try:
            # Start writer process
            writer = mp.Process(
                target=writer_process, 
                args=(result_queue, output_path, total_passwords, stop_event)
            )
            writer.start()
            
            # Start worker processes
            workers = []
            for i in range(self.num_processes):
                p = mp.Process(
                    target=worker_process,
                    args=(task_queue, result_queue, self.config, i)
                )
                p.start()
                workers.append(p)
            
            # Monitor progress
            last_count = 0
            last_time = start_time
            
            while any(w.is_alive() for w in workers):
                time.sleep(self.config['progress_update_interval'])
                current_count = total_passwords.value
                current_time = time.time()
                
                elapsed = current_time - start_time
                rate = current_count / elapsed if elapsed > 0 else 0
                
                # Calculate recent rate
                recent_elapsed = current_time - last_time
                recent_rate = (current_count - last_count) / recent_elapsed if recent_elapsed > 0 else 0
                
                print(f"Generated: {current_count:,} passwords (avg: {rate:,.0f} p/s, current: {recent_rate:,.0f} p/s)")
                
                last_count = current_count
                last_time = current_time
            
            # Wait for all workers to complete
            for w in workers:
                w.join()
            
            # Signal writer to stop and wait
            stop_event.set()
            writer.join()
            
        except KeyboardInterrupt:
            print(f"\nInterrupted. Stopping all processes...")
            stop_event.set()
            for w in workers:
                w.terminate()
            writer.terminate()
            sys.exit(1)
        except Exception as e:
            print(f"\nError occurred: {e}")
            traceback.print_exc()
            stop_event.set()
            sys.exit(1)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n=== Generation Complete ===")
        print(f"Total passwords generated: {total_passwords.value:,}")
        print(f"Total time: {duration:.2f} seconds")
        print(f"Average rate: {total_passwords.value/duration:,.0f} passwords/second")
        print(f"Saved to: {self.output_file}")
        print(f"\nIMPORTANT: Run 'python deduplicate_wordlist.py {self.output_file}' to remove duplicates.")


if __name__ == "__main__":
    # Required for Windows
    mp.freeze_support()
    
    print("=== Multi-Process Wordlist Generator ===")
    print(f"Using {mp.cpu_count()} CPU cores")
    
    generator = MultiProcessWordlistGenerator(CONFIG)
    
    try:
        generator.validate_config()
    except ValueError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    
    total_combinations, estimated_size_gb = generator.estimate_file_size()
    
    print("\n--- Estimation ---")
    print(f"Estimated passwords: {total_combinations:,}")
    print(f"Estimated size: {estimated_size_gb:.2f} GB")
    print("Note: May contain duplicates - run deduplication script after generation.")
    
    if estimated_size_gb > 5:
        print("\n!!! WARNING !!!")
        print("Large file size. Consider reducing parameters.")
    
    confirm = input("\nProceed? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        sys.exit(0)
    
    while True:
        output_path = input("Output path: ").strip()
        if not output_path:
            print("Error: Path cannot be empty.")
            continue
            
        directory = os.path.dirname(output_path) or '.'
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Created directory: {directory}")
            except OSError:
                print(f"Error: Cannot create directory.")
                continue
        
        try:
            temp_path = os.path.join(directory, 'temp_write_test.txt')
            with open(temp_path, 'w') as f:
                f.write("test")
            os.remove(temp_path)
            break
        except IOError:
            print(f"Error: Cannot write to directory.")
            continue
    
    generator.generate_wordlist(output_path)