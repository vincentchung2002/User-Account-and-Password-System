import random
import string
import json
import hashlib
import re
import datetime


class Login:
    
    def __init__(self, filepath):
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
        if make_password:
            return None
        elif make_password == False:
            return input("Enter your own hint: ")
    
    def is_valid_username(self, username):
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
        hashed_username = hashlib.sha256(username.encode()).hexdigest()
        user_data = {
            "hash_username": hashed_username,
            "hashed_password": hashlib.sha256(password.encode()).hexdigest(),
            "strength": strength,
            "firstname": firstname,
            "lastname": lastname
        }

        self.stored_data.update({hashed_username: user_data})

        with open(self.filepath, 'w', encoding='utf-8') as file:
            json.dump(self.stored_data, file, indent=2)

    def feedback_on_strength(self,strength):
        specific_feedback = {
            'weak': 'Consider adding more variety such as special characters or an uppercase letter to improve the strength.',
            'medium': 'You can enhance the strength by adding more characters and variety.',
            'strong': ' Great job! It meets all the requirements.'
        }

        feedback_message = specific_feedback.get(strength, 'Invalid strength value')

        return f"The strength of your password is: {strength.capitalize()}. {feedback_message}" if strength in specific_feedback else "Invalid strength value"

    def simulate_login(self):
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
                        break
                    else:
                        print("Login Unsuccessful")
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
