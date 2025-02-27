
# Password Manager 3.0

Password Manager 3.0 is a secure, user-friendly application for managing and storing passwords. Built using PyQt6, it offers advanced features, including password generation, encryption, and a user-friendly GUI.

## Features

- **Master Password Security**: Protect your stored passwords with a master password.
- **Secure Password Encryption**: Passwords are encrypted using the `cryptography` library.
- **Password Management**: Add, view, modify, or delete stored credentials.
- **Password Generation**: Generate secure passwords with customizable strength.
- **Clipboard Integration**: Copy generated passwords directly to your clipboard.
- **SQLite Database Integration**: Passwords are securely stored in an SQLite database.
- **User-Friendly Interface**: A clean and intuitive GUI using PyQt6.

## Prerequisites

- Python 3.12 or newer
- Required Python libraries:
  - `PyQt6`
  - `cryptography`
  - `sqlite3` (built-in with Python)
- Optional:
  - An icon image file (`icon.png`) stored in the `resources/` folder.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/password-manager.git
   cd password-manager
   ```

2. Install dependencies:
   ```bash
   pip install PyQt6 cryptography
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage

1. **First Time Setup**:
   - Set a master password during the initial launch.
   - The master password secures access to your stored credentials.

2. **Adding Passwords**:
   - Enter the username, password, and optional service name.
   - Use the "Add" button to store the credentials.

3. **Viewing Passwords**:
   - Navigate to the "Show Saved Passwords" section.
   - Select an entry to view or delete its password.

4. **Generating Passwords**:
   - Use the "Generate Password" button on the main page.
   - The password is securely generated and copied to your clipboard.

5. **Modifying Passwords**:
   - Enter the username and new password in the "Modify Password" section.
   - Confirm the master password to apply changes.

## File Structure

- `main.py`: Main application code.
- `resources/icon.png`: Application icon (optional).
- `passwords.db`: SQLite database (automatically generated).
- `secret.key`: Encryption key (automatically generated).

## Security

- Passwords are encrypted using the Fernet encryption scheme from the `cryptography` library.
- The encryption key is securely stored locally in the `secret.key` file.
- Always back up your database (`passwords.db`) and encryption key (`secret.key`) together.

## Limitations

- The application is designed for local use. Ensure your system is secure to protect stored passwords.
- Losing the `secret.key` file will render stored passwords irretrievable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contribution

Feel free to submit issues or pull requests to improve this project.

## Acknowledgments

- Built with PyQt6 for an elegant UI experience.
- Encryption powered by the `cryptography` library.
