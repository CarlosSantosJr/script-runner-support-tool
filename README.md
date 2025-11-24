# Script Runner Support Tool

## Introduction
The **Script Runner Support Tool** is a web-based application designed to streamline support operations by providing a centralized interface for managing and executing Python scripts. Built with Flask and Flask-SocketIO, it offers a user-friendly environment to:

*   **Manage Customers**: Maintain a database of customer configurations, including credentials and AWS Cognito details.
*   **Script Library**: Upload, update, and organize a collection of support scripts.
*   **Interactive Execution**: Run Python scripts directly from the browser with real-time input/output capabilities (via WebSockets), acting as a web-based terminal.
*   **Authentication Helper**: Automatically generate AWS Cognito tokens for customers to be used within scripts that require authentication.

## Prerequisites
*   **Python 3.x**: Ensure Python is installed on your system.
*   **pip**: Python package installer.

## Installation

1.  **Clone the repository** (if applicable) or navigate to the project directory.

2.  **Create a virtual environment** (recommended):
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Setup Scripts**:
    *   Manually create a folder named `scripts` in the project root directory.
    *   Manually copy your Python scripts (`.py` files) into this `scripts` folder.
    *   *(Note: The web interface upload functionality is currently not working, so manual placement is required).*

## Running the Application

1.  **Start the Flask server**:
    ```bash
    python app.py
    ```

2.  **Access the application**:
    Open your web browser and navigate to:
    [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Usage Guide

### Dashboard
The main dashboard lists available scripts and customers. Select a script and a customer to proceed to the execution page.

### Managing Customers
*   Navigate to the **Configuration** page (via the "Manage Customers" link).
*   Add new customers by providing their Name, Username, Password, Client ID, and AWS Region.
*   Edit or delete existing customer entries.

### Managing Scripts
*   Navigate to the **Manage Scripts** page.
*   **Upload**: Add new `.py` scripts to the library. You can specify if a script requires user input or an authentication token.
*   **Edit/Delete**: Update existing scripts or remove them from the system.
*   **Important Note**: Currently, the upload functionality is under maintenance. Please manually place your `.py` files into the `scripts/` directory. You can still use this page to configure script requirements.

### Executing Scripts
1.  Select a script and a customer from the Dashboard.
2.  Click **"Next"** to go to the Execution Page.
3.  If the script requires a token, the system can generate one using the selected customer's credentials.
4.  Click **"Start Execution"**.
5.  Interact with the script in the terminal window. You can type inputs and see real-time outputs.
6.  Use **"Stop Execution"** to terminate a running script.

## Project Structure
*   `app.py`: Main Flask application file containing backend logic and routes.
*   `templates/`: HTML templates for the user interface.
*   `static/`: Static assets (CSS, JS).
*   `scripts/`: Directory where uploaded Python scripts are stored.
*   `customers.json`: JSON storage for customer data.
*   `scripts_metadata.json`: JSON storage for script configuration (input/token requirements).
*   `requirements.txt`: List of Python dependencies.