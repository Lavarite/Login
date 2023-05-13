import tkinter as tk
from threading import Thread
from tkinter import messagebox
import re
import threading
import asyncio

from Confirm import confirmation_links, email_search, request_confirmation, app


class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password
        self.confirmed = False

    def __repr__(self):
        return f'User({self.username!r}, {self.email!r}, {self.password!r})'

    def __eq__(self, other):
        return (self.username == other.username or self.email == other.email) and self.password == other.password

    def __hash__(self):
        return hash(self.username) ^ hash(self.email)

    def is_confirmed(self):
        return self.confirmed

    def is_valid(self):
        return self.username and self.email and self.password


# Mock database
users = []
buttonClicked = False

async def wait_until_confirmed(username, email, password, loop):
    global buttonClicked
    while True:
        if confirmation_links:
            results = email_search(email)
            l = results[0][0]
            stats = results[0][1][1]
            if stats == 1:
                print('check')
                # Create a new user and add it to the database
                new_user = User(username, email, password)
                users.append(new_user)
                keys_to_remove = [key for key in confirmation_links if key == l]
                for key in keys_to_remove:
                    confirmation_links.pop(key, None)
                show_email_confirmed()
                loop.stop()
            if buttonClicked:
                loop.stop()
                buttonClicked = False
            await asyncio.sleep(1)


def show_email_confirmed():
    register_frame.forget()
    email_confirmed_frame.pack()


def show_logged_in_page(username, password):
    login_frame.forget()
    logged_in_frame.pack()
    logged_in_username_label.config(text=f'Your Username: {username}')
    logged_in_password_label.config(text=f'Your Password: {password}')


def show_register_page():
    toggle_register_password_button.config(text='●')
    update_password_strength_checklist()
    main_frame.pack_forget()
    register_frame.pack()


def show_login_page():
    toggle_login_password_button.config(text='●')
    email_confirmed_frame.pack_forget()
    main_frame.pack_forget()
    login_frame.pack()


def show_main_page():
    register_password.delete(0, 'end')
    register_username.delete(0, 'end')
    register_email.delete(0, 'end')
    login_password.delete(0, 'end')
    login_username.delete(0, 'end')
    register_password.config(show='*')
    login_password.config(show='*')
    register_frame.pack_forget()
    login_frame.pack_forget()
    email_confirmed_frame.forget()
    main_frame.pack()


def check_password_strength(password):
    requirements = {
        'Length (8 characters or more)': len(password) >= 8,
        'At least 1 uppercase letter': bool(re.search(r'[A-Z]', password)),
        'At least 1 digit': bool(re.search(r'\d', password)),
        'At least 1 special character': bool(re.search(r'[@#$%^&+=]', password))
    }
    return requirements


def update_password_strength_checklist():
    password = register_password.get()
    requirements = check_password_strength(password)

    for i, (requirement, is_met) in enumerate(requirements.items()):
        check_label = password_checklist_labels[i]
        if is_met:
            check_label.config(text='\u2713 ' + requirement, fg='green')
        else:
            check_label.config(text='\u2717 ' + requirement, fg='red')

    register_button.config(state=tk.NORMAL if all(requirements.values()) else tk.DISABLED)


def toggle_password_visibility(entry):
    current_state = entry['show']
    toggle_login_password_button.config(text='○' if current_state else '●')
    toggle_register_password_button.config(text='○' if current_state else '●')
    entry.config(show='' if current_state else '*')


def is_valid_email(email):
    # Simple email validation using regex
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    register_email.config(fg='green' if re.match(pattern, email) else 'red')
    return re.match(pattern, email)


def register():
    username = register_username.get()
    email = register_email.get()
    password = register_password.get()

    if username == '' or email == '' or password == '':
        messagebox.showerror('Error', 'Please fill in all fields.')
        return

    # Check if the username already exists in the database.
    for user in users:
        if user.username == username:
            messagebox.showerror('Error', 'Username already exists.')
            return

    # Check if the email already exists in the database.
    for user in users:
        if user.email == email:
            messagebox.showerror('Error', 'Username already exists.')
            return

    # Check if the email is valid.
    if not is_valid_email(email):
        messagebox.showerror('Error', 'Invalid email.')
        return

    # Check if the email already exists in the database.
    for user in users:
        if user.email == email:
            messagebox.showerror('Error', 'Email already exists.')
            return

    # Check the password strength
    requirements = check_password_strength(password)
    if not all(requirements.values()):
        messagebox.showerror('Error', 'Please enter a strong password.')
        return

    request_confirmation(email)

    messagebox.showinfo("Email confirmation", 'Sent email confirmation letter to your inbox!')

    def run_confirmation(username, email, password):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.ensure_future(wait_until_confirmed(username, email, password,loop))
        loop.run_forever()

    confirmation_thread = threading.Thread(target=run_confirmation, args=(username, email, password))
    confirmation_thread.start()


def login():
    username_or_email = login_username.get()
    password = login_password.get()

    if username_or_email == '' or password == '':
        messagebox.showerror('Error', 'Please fill in all fields.')
        return

    # Check if the user exists in the database.
    user = None
    for u in users:
        if u.username == username_or_email or u.email.lower() == username_or_email.lower():
            user = u
            break

    if user is None:
        messagebox.showerror('Error', 'User not found.')
        return

    # Check if the password is correct.
    if password != user.password:
        messagebox.showerror('Error', 'Invalid password.')
        return

    # Login successful!
    messagebox.showinfo('Success', 'Login successful!')

    # Clear the login form
    login_username.delete(0, tk.END)
    login_password.delete(0, tk.END)

    # Return to the main page
    show_logged_in_page(user.username, password)


# Create the main window
window = tk.Tk()
window.title('Login and Register')

# Create the main frame
main_frame = tk.Frame(window, padx=10, pady=10)
main_frame.pack()

# Create the register button
register_button = tk.Button(main_frame, text='Register', command=show_register_page)
register_button.pack(pady=10)

# Create the login button
login_button = tk.Button(main_frame, text='Log In', command=show_login_page)
login_button.pack(pady=10)

# Create the registration frame
register_frame = tk.Frame(window, padx=10, pady=10)

# Create the username label
register_username_label = tk.Label(register_frame, text='Username:')
register_username_label.grid(row=0, column=0)

# Create the username entry
register_username = tk.Entry(register_frame)
register_username.grid(row=0, column=1)

# Create the password label
register_password_label = tk.Label(register_frame, text='Password:')
register_password_label.grid(row=1, column=0)

# Create the password entry
register_password = tk.Entry(register_frame, show='*')
register_password.grid(row=1, column=1)
register_password.bind('<KeyRelease>', lambda event: update_password_strength_checklist())

# Create the password label
register_email_label = tk.Label(register_frame, text='Email:')
register_email_label.grid(row=2, column=0)
# Create the email entry
register_email = tk.Entry(register_frame)
register_email.grid(row=2, column=1)
register_email.bind('<KeyRelease>', lambda event: is_valid_email(register_email.get()))

# Create the password strength checklist
password_checklist_labels = []
requirements = check_password_strength('')
for i, requirement in enumerate(requirements.keys()):
    check_label = tk.Label(register_frame, text='', anchor='w')
    check_label.grid(row=i + 3, column=1, sticky='w')
    password_checklist_labels.append(check_label)
for i, (requirement, is_met) in enumerate(requirements.items()):
    check_label = password_checklist_labels[i]
    if is_met:
        check_label.config(text='\u2713 ' + requirement, fg='green')
    else:
        check_label.config(text='\u2717 ' + requirement, fg='red')

# Create the register button
register_button = tk.Button(register_frame, text='Register', command=register, state=tk.DISABLED)
register_button.grid(row=len(requirements) + 3, columnspan=2)


def register_back(email):
    global buttonClicked
    buttonClicked = True
    try:
        results = email_search(email)
        l = results[0][0]
        confirmation_links.pop(l)
        print(confirmation_links.keys())
    except Exception:
        pass
    show_main_page()


# Create the back button
back_button = tk.Button(register_frame, text='Back', command=lambda: register_back(email=register_email.get()))
back_button.grid(row=len(requirements) + 4, columnspan=2)

# Create the login frame
login_frame = tk.Frame(window, padx=10, pady=10)

# Create the username label
login_username_label = tk.Label(login_frame, text='Username:')
login_username_label.grid(row=0, column=0)

# Create the username entry
login_username = tk.Entry(login_frame)
login_username.grid(row=0, column=1)

# Create the password label
login_password_label = tk.Label(login_frame, text='Password:')
login_password_label.grid(row=1, column=0)

# Create the password entry
login_password = tk.Entry(login_frame, show='*')
login_password.grid(row=1, column=1)

# Create the login button
login_button = tk.Button(login_frame, text='Log In', command=login)
login_button.grid(row=2, columnspan=2)

# Create the back button
back_button = tk.Button(login_frame, text='Back', command=show_main_page)
back_button.grid(row=3, columnspan=2)

# Create logged in landing page
logged_in_frame = tk.Frame(window, padx=10, pady=10)

logged_in_username_label = tk.Label(logged_in_frame, text='Your Username: ')
logged_in_username_label.grid(row=0, column=0)
logged_in_password_label = tk.Label(logged_in_frame, text='Your Password: ')
logged_in_password_label.grid(row=1, column=0)

# Create a button to toggle password visibility in the registration frame
toggle_register_password_button = tk.Button(register_frame, text='●',
                                            command=lambda: toggle_password_visibility(register_password), bd=0,
                                            relief=tk.FLAT)
toggle_register_password_button.grid(row=1, column=2, columnspan=2, rowspan=2)

# Create a button to toggle password visibility in the login frame
toggle_login_password_button = tk.Button(login_frame, text='●',
                                         command=lambda: toggle_password_visibility(login_password), bd=0,
                                         relief=tk.FLAT)
toggle_login_password_button.grid(row=1, column=2, columnspan=2, rowspan=2)

email_confirmed_frame = tk.Frame(window, padx=10, pady=10)

confirmed_label = tk.Label(email_confirmed_frame, text='Registration successful! Your email has been confirmed.')
confirmed_label.grid(row=1, column=1)

confirmed_login_button = tk.Button(email_confirmed_frame, text='Log In', command=show_login_page)
confirmed_login_button.grid(row=2, column=1)

confirmed_back_button = tk.Button(email_confirmed_frame, text='Back', command=show_main_page)
confirmed_back_button.grid(row=3, column=1)

if __name__ == '__main__':
    Thread(target=app.run, kwargs={'debug': True, 'use_reloader': False}).start()
    window.mainloop()
