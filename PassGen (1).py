import random
import string
import json
import hashlib
import re
import datetime


class Login:
    """
    A class representing a user login system.

    This class provides functionality for generating random usernames and passwords,
    analyzing password strength, checking password age, and simulating a user login process.

    """
    def __init__(self, filepath):
        """
        Initializes an instance of the Login class with an empty dictionary to store user data.
        """
        
        self.filepath = filepath
        try:
            with open(filepath, 'r', encoding = 'utf-8') as file:
                try:
                    self.stored_data = json.load(file)
                except json.JSONDecodeError:
                    self.stored_data = {}
        except FileNotFoundError:
            self.stored_data = {}
            
    def generate_username(self, firstname=None, lastname=None):
        """
        Siya Patel
        Generates a username based on user input or randomly if chosen.

        Args:
            firstname (str): The user's first name.
            lastname (str): The user's last name.

        Returns:
            str: The generated or user-input username.
            
        Technique used: optional parameters, f-strings
        """
        while True:
            use_random = input("Do you want to use a random username? (yes/no): ").lower()
            if use_random == 'yes':
                if firstname:
                    username = firstname.lower()
                else:
                    username = ''
                all_characters = string.ascii_letters + string.digits
                random_string = ''.join(random.choice(all_characters) for _ in range(4))
                username += random_string
                print(f"Your username is {username}")
            elif use_random == 'no':
                username = input("Enter your username: ")
            else:
                print("Invalid input. Please choose 'yes' or 'no'.")
                continue

            if self.is_valid_username(username):
                return username
            else:
                print("Invalid username. The username must contain both letters and numbers.")


    def generate_password(self):
        """
        Claude Willard 
        Allows user to generate a random password or enter a custom one.

        The user is first prompted to choose whether to generate a random password. If they choose to generate one,
        they must specify the desired length and complexity ('low', 'medium', or 'high'). The function validates the
        user's input for both length and complexity, ensuring that the length meets the minimum requirements for the
        selected complexity. A random password is then generated based on specifications unless user chooses not to
        generate a password, they are prompted to input their own. The method loops until valid input is received or
        the user provides a custom password.

        Side Effects:
            - The user is prompted through standard input to make choices and enter data.
            - If a random password is generated, a record of the password with info (length,
            complexity, and timestamp) is appended to a 'password_log.json' file.
            - Prints the generated password or a message to the console.

        Returns:
            str: The generated random password or the user-entered password.

        Raises:
            ValueError: If the user enters a non-integer value for the password length.
            ValueError: If the password length is less than the minimum required for the chosen complexity.
            
        Technique used: json.dump
        """
        password = None  
        hint = None
        while True:
            use_random = input("Do you want to generate a random password? (yes/no): ").lower()
            if use_random == 'yes':
                while True:
                    try:
                        length = int(input("Enter the desired password length: "))
                        complexity = input("Enter the desired password complexity (low/medium/high): ").lower().strip()
                        if complexity not in ['low', 'medium', 'high']:
                            print("Invalid complexity level. Please choose 'low', 'medium', or 'high'.")
                            continue
                        break
                    except ValueError:
                        print("Please enter a valid number for password length.")
                
                minimum_lengths = {
                    "low": 6,
                    "medium": 8,
                    "high": 12
                }

                if length < minimum_lengths[complexity]:
                    print(f"Password length must be at least {minimum_lengths[complexity]} for {complexity} complexity")
                    continue

                complexity_levels = {
                    "low": string.ascii_lowercase,
                    "medium": string.ascii_letters + string.digits,
                    "high": string.ascii_letters + string.digits + string.punctuation
                }

                password = ''.join(random.choice(complexity_levels[complexity]) for _ in range(length))
                print(f'Your password is {password}')

                password_data = {
                    'password': password,
                    'length': length,
                    'complexity': complexity,
                    'timestamp': str(datetime.datetime.now())
                }

                with open('password_log.json', 'a') as file:
                    file.write(json.dumps(password_data) + '\n')
                break

            elif use_random == 'no':
                password = input("Enter your own password: ")
                self.generate_hint()
                break  
            else:
                print("Invalid input. Please choose 'yes' or 'no'.")

        return password, hint

    def generate_hint(self, make_password = True):
        """
        Daniel Gwira
        Generate a random hint or allow the user to input their own hint.

        Args:
            make_password (bool): A flag indicating whether the user is making their own password.

        Returns:
            str or None: A randomly generated hint or user-input hint.
            
        Technique used: keyword arguments
        """
    
        if make_password:
            return None
        elif make_password == False:
            return input("Enter your own hint: ")
    
    def is_valid_username(self, username):
        """
        Siya Patel 
        Checks if the provided username is valid based on certain criteria.

        Args:
            username (str): The username to be validated.

        Returns:
            bool: True if the username is valid, False otherwise.
            
        Technique: conditional expressions
        """
        if len(username) < 5:
            print("Username must be at least 5 characters long.")
            return False

        if not any(char.isdigit() for char in username) or not any(char.isalpha() for char in username):
            print("Username must contain both letters and numbers.")
            return False

        allowed_characters = set(string.ascii_letters + string.digits + "_")
        if not all(char in allowed_characters for char in username):
            print("Invalid characters in the username. Only letters, numbers, and underscores are allowed.")
            return False

        return True
    
    def check_strength(self, password):
        """
        Lennon Brosoto
        Check the strength of a password based on various criteria.

        Args:
            password (str): The password to be checked.

        Returns:
            -str: The strength value, which can be 'weak', 'medium', or 'strong'.
            
        Technique used: regular expressions
        """

        length = len(password)

        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        criteria = {
            'weak': (length < 6 or not any([has_uppercase, has_digit, has_special])),
            'medium': (length >= 7 and any([has_uppercase, has_digit, has_special]) and not all([has_uppercase, has_digit, has_special])),
            'strong': (length >= 12 and all([has_uppercase, has_digit, has_special]))
        }

        for strength, meets_criteria in criteria.items():
            if meets_criteria:
                return strength
            

    def structure(self, username, password, hint, strength, firstname = None, lastname = None):
        """ 
        Daniel Gwira
        Create a new user with the given credentials and save the data to a JSON file.

        Args:
            - username (str): The username of the new user.
            - password (str): The password for the new user.
            - hint (str): A hint related to the password.
            - strength (str): Strength of the password.

        Returns:
            - None
        
        Technique used: hashlib module
        """
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        user_data = {
            "hash_username": hashed_username,
            "hashed_password": hashlib.sha256(password.encode()).hexdigest(),
            "hint": hint,
            "strength": strength,
            "firstname": firstname,
            "lastname": lastname
        }

        self.stored_data.update({hashed_username: user_data})

        with open(self.filepath, 'w', encoding='utf-8') as file:
            json.dump(self.stored_data, file, indent=2)

    def feedback_on_strength(self,strength):
        """
        Lennon Brosoto
        Provide detailed feedback based on the strength value and specific criteria.

        Args:
            - strength (str): The password strength value.

        Returns:
        - str: Detailed feedback on the strength of the password.
        
        Technique used: f strings
        """
        specific_feedback = {
            'weak': 'Consider adding more variety such as special characters or an uppercase letter to improve the strength.',
            'medium': 'You can enhance the strength by adding more characters and variety.',
            'strong': ' Great job! It meets all the requirements.'
        }

        feedback_message = specific_feedback.get(strength, 'Invalid strength value')

        return f"The strength of your password is: {strength.capitalize()}. {feedback_message}" if strength in specific_feedback else "Invalid strength value"

    def password_age_check(self, username, filepath='password_log.json'):
        """
        Claude Willard
        Checks how old a user's password is and advises if it's time to change it (90 days max).

        Args:
            username (str): The username of the user.
            filepath (str): The path to the password log JSON file. Default is 'password_log.json'.

        Returns:
            None
            
        Technique used: optional parameters
        """
        try:
            with open(filepath, 'r') as file:
                password_logs = file.readlines()
            hashed_username = hashlib.sha256(username.encode()).hexdigest()
            stored_password_hash = None  
            for log in password_logs:
                data = json.loads(log)
                if data.get('hashed_username') == hashed_username:
                    stored_password = data.get('password')
                    stored_password_hash = hashlib.sha256(stored_password.encode()).hexdigest()
                    password_timestamp = datetime.datetime.fromisoformat(data['timestamp'])
                    current_time = datetime.datetime.now()
                    age_days = (current_time - password_timestamp).days
                    if stored_password_hash == hashlib.sha256(stored_password.encode()).hexdigest():
                        if age_days > 90:
                            print(f"Your password is {age_days} days old. It is recommended to change your password.")
                        else:
                            print(f"Your password is {age_days} days old. No need to change now.")
                        return
            if stored_password_hash is None:
                print("Password not found in password log.")
        except FileNotFoundError:
            print(f"File not found: {filepath}")

    
    def simulate_login(self):
        """
        Vincent Chung
        Simulates a user login process.

        Args:
            None

        Returns:
            None
            
        Technique used: sequence unpacking
        """
        while True:
            print("------------------------------------------------------- Group B Alliance -------------------------------------------------------")
            action = input("1. Login\n2. Create an account\n3. Exit\nEnter the number corresponding to your choice: ")
            if action == '1':
                for log in range(3):
                    username = input("USERNAME: ")
                    password = input("PASSWORD: ")
                    hashed_username = hashlib.sha256(username.encode()).hexdigest()
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    if hashed_username in self.stored_data and self.stored_data[hashed_username]["hashed_password"] == hashed_password:
                        print("Login successful!")
                        check_password_age = input("Do you want to check the age of your password? (yes/no): ").lower()
                        if check_password_age == 'yes':
                            self.password_age_check(hashed_username)
                        return
                    else:
                        print("Login Unsuccessful")
                    print("Incorrect password. If you forgot your password, here's a hint:")
                    print(self.stored_data.get(hashed_username, {}).get("hint", "No hint available."))
                print("Too many incorrect attempts. Account locked.")
            elif action == '2':
                firstname = input("Enter your first name: ")
                lastname = input("Enter your last name: ")
                username = self.generate_username(firstname=firstname)
                password, hint = self.generate_password()
                if password is None:
                    print("Cannot create an account without a password. Exiting.")
                    break

                strength = self.check_strength(password)
                feedback = self.feedback_on_strength(strength)
                self.structure(username, password, hint, strength, firstname, lastname)
                print(feedback)
                print("Account created successfully!\n------------------------------------------------------- Welcome to Group B Alliance -------------------------------------------------------")
                break
            elif action == '3':
                print('Exiting code. Goodbye!')
                exit()
            else:
                print("Invalid choice. Please choose 1 or 2.")
                break
            
if __name__ == '__main__':
    filepath = 'user_pass_file.json'
    login_instance = Login(filepath)
    login_instance.simulate_login()
