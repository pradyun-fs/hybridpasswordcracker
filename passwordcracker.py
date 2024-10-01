import itertools
import string
import time
import multiprocessing
from tqdm import tqdm
# cooked by Pradyun Subash


# Dictionary attack feature
def dictionary_attack(target_password, wordlist_file):
    print("Starting dictionary attack...")
    print("")
    try:
        with open(wordlist_file, "r") as file:
            for word in tqdm(file, desc="Trying passwords from dictionary"):
                word = word.strip()  # Remove newline
                if word == target_password:
                    return word
    except FileNotFoundError:
        print(f"Wordlist file {wordlist_file} not found.")
    return None


# Brute-force attack function with early exit
def brute_force_attack(
    target_password, characters, min_length, max_length, stop_event, time_limit=None
):
    start_time = time.time()
    for password_length in range(min_length, max_length + 1):
        total_combinations = len(characters) ** password_length
        for guess in tqdm(
            itertools.product(characters, repeat=password_length),
            total=total_combinations,
            desc=f"Trying length {password_length}",
        ):
            guess_password = "".join(guess)

            # Check for timeout
            if time_limit and (time.time() - start_time) > time_limit:
                print("\nTime limit exceeded. Stopping the attack.")
                print("")
                stop_event.set()
                return None

            # Stop if user requests it
            if stop_event.is_set():
                return None

            if guess_password == target_password:
                stop_event.set()
                return guess_password
    return None


# Multiprocessing to divide brute-force work
def parallel_brute_force(
    target_password, characters, min_length, max_length, time_limit=None
):
    manager = multiprocessing.Manager()
    stop_event = manager.Event()
    pool = multiprocessing.Pool(
        processes=multiprocessing.cpu_count()
    )  # Use all available CPU cores

    results = []
    for password_length in range(min_length, max_length + 1):
        results.append(
            pool.apply_async(
                brute_force_attack,
                (
                    target_password,
                    characters,
                    password_length,
                    password_length,
                    stop_event,
                    time_limit,
                ),
            )
        )

    pool.close()
    pool.join()

    for result in results:
        if result.get():
            return result.get()
    return None


# Save progress and resume functionality
def save_progress(guess_password, filename="progress.txt"):
    with open(filename, "w") as file:
        file.write(guess_password)


def load_progress(filename="progress.txt"):
    try:
        with open(filename, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


# Main function to control features
def start_brute_force(target_password):
    # User can choose a custom character set
    print("Select character set:")
    print("1. Lowercase letters")
    print("2. Uppercase letters")
    print("3. Digits")
    print("4. Punctuation")
    print("5. All characters")
    print("")

    option = input("Enter the number for the character set: ")
    print("")
    if option == "1":
        characters = string.ascii_lowercase
    elif option == "2":
        characters = string.ascii_uppercase
    elif option == "3":
        characters = string.digits
    elif option == "4":
        characters = string.punctuation
    elif option == "5":
        characters = (
            string.ascii_lowercase
            + string.ascii_uppercase
            + string.digits
            + string.punctuation
        )
    else:
        print("")
        print("Invalid option, using all characters.")
        characters = (
            string.ascii_lowercase
            + string.ascii_uppercase
            + string.digits
            + string.punctuation
        )

    # User input for password length range
    min_length = int(input("Enter minimum password length: "))
    max_length = int(input("Enter maximum password length: "))

    # Ask user for time limit (optional)
    try:
        print("")
        time_limit = int(input("Enter time limit in seconds (0 for no limit): "))
    except ValueError:
        time_limit = 0

    # Dictionary attack option
    print("")
    use_dictionary = input("Use dictionary attack? (y/n): ").lower()
    if use_dictionary == "y":
        wordlist_file = r"C:\Users\prady\OneDrive\Documents\rockyou.txt"
        result = dictionary_attack(target_password, wordlist_file)
        if result:
            print("")
            print(f"Password found using dictionary: {result}")
            return
        else:
            print("")
            print("Dictionary attack failed. Moving to brute-force...")

    # Start brute-force attack and measure time
    start_time = time.time()
    print("Brute-forcing, please wait...")

    # Use multiprocessing for brute-forcing
    found_password = parallel_brute_force(
        target_password,
        characters,
        min_length,
        max_length,
        time_limit if time_limit > 0 else None,
    )

    end_time = time.time()

    if found_password:
        print(f"\nPassword found: {found_password}")
        save_progress(found_password)
    else:
        print("\nPassword not found.")

    print(f"Time taken: {end_time - start_time:.2f} seconds")


# Example usage
if __name__ == "__main__":
    target_password = input("Enter your password")  # take user input password
    start_brute_force(target_password)
