from flask import Flask, render_template, request
from colorama import Fore, Back, Style, init
from passlib.hash import sha256_crypt
import re
import subprocess
import platform



import mysql.connector

app = Flask(__name__,template_folder='')

def is_password_hashed(password):
    # This function checks if the password is hashed using sha256_crypt
    return sha256_crypt.identify(password)

def is_strong_password(password):
    # Convert bytes to string if necessary
    password_str = password.decode('utf-8') if isinstance(password, bytes) else password

    # This function checks if the password meets certain strength criteria
    # (You can customize the criteria based on your security requirements)
    if len(password_str) < 8:
        return False
    if not re.search("[a-z]", password_str):
        return False
    if not re.search("[A-Z]", password_str):
        return False
    if not re.search("[0-9]", password_str):
        return False
    return True


def check_database_security(host, user, password, output_file_path,db):
    try:
        # Connect to MySQL
        connection=None
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=db
        )

        # Create a cursor object to execute SQL queries
        if connection.is_connected():
            cursor = connection.cursor()

        # Check for default usernames and passwords
        cursor.execute("SELECT user, host FROM mysql.user WHERE authentication_string IN ('', 'password')")
        default_credentials = cursor.fetchall()

        # Check for unnecessary services running
        cursor.execute("SHOW VARIABLES LIKE 'have_%'")
        unnecessary_services = [var for var in cursor.fetchall() if var[1] == 'YES']

        # Check for overly permissive access controls
        cursor.execute("SHOW GRANTS")
        access_controls = cursor.fetchall()

        # Filter users with more than three privileges
        privileged_users = [user for user in access_controls if user[0].count(",") >= 2]
        cursor.execute("SELECT user, host, authentication_string FROM mysql.user")
        users = cursor.fetchall()

        # Display and save results to a file for privileged users
        with open(output_file_path, 'w') as output_file:
            output_file.write("Checking database security:\n")
            
            for user_info in users:
                username, host, auth_string = user_info
                hashed_password = is_password_hashed(auth_string)
                strong_password = is_strong_password(auth_string)

                print(f"User: {username}@{host}")
                output_file.write(f"User: {username}@{host}\n")
                print(f"   - Password Hashed: {hashed_password}")
                output_file.write(f"   - Password Hashed: {hashed_password}\n")
                print(f"   - Strong Password: {strong_password}")
                output_file.write(f"   - Strong Password: {strong_password}\n")

            # Check for default usernames and passwords
            if default_credentials:
                output_file.write("   Default usernames and/or passwords found:\n")
                for cred in default_credentials:
                    output_file.write(f"      User: {cred[0]}, Host: {cred[1]}\n")

            # Check for unnecessary services running
            if unnecessary_services:
                output_file.write("   Unnecessary services running:\n")
                for service in unnecessary_services:
                    output_file.write(f"      {service[0]}\n")

            # Check for overly permissive access controls for privileged users
            if privileged_users:
                output_file.write("   Users with more than three privileges:\n")
                for user in privileged_users:
                    output_file.write(f"      {user[0]}\n")
            
                
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

            # Display results
            if tables:
                print("Checking security settings for each table:")
                for table in tables:
                    table_name = table[0]

                    # Check if secure_auth is enabled for the current table
                    cursor.execute(f"SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table_name}' AND COLUMN_NAME = 'password'")
                    secure_auth_result = cursor.fetchone()
                    secure_auth_enabled = secure_auth_result is not None

                    # Check if enforce_gtid_consistency is enabled for the current table
                    cursor.execute(f"SHOW VARIABLES LIKE 'enforce_gtid_consistency'")
                    enforce_gtid_result = cursor.fetchone()
                    enforce_gtid_enabled = enforce_gtid_result[1] == 'ON' if enforce_gtid_result else None

                    # Check if general_log is disabled for the current table
                    cursor.execute(f"SHOW VARIABLES LIKE 'general_log'")
                    general_log_result = cursor.fetchone()
                    general_log_disabled = general_log_result[1] == 'OFF' if general_log_result else None

                    print(f"Table '{table_name}': secure_auth enabled: {secure_auth_enabled}")
                    output_file.write(f"Table '{table_name}': secure_auth enabled: {secure_auth_enabled}")
                    print(f"Table '{table_name}': enforce_gtid_consistency enabled: {enforce_gtid_enabled}")
                    output_file.write(f"Table '{table_name}': enforce_gtid_consistency enabled: {enforce_gtid_enabled}\n")
                    print(f"Table '{table_name}': general_log disabled: {general_log_disabled}")
                    output_file.write(f"Table '{table_name}': general_log disabled: {general_log_disabled}\n")
            output_file.write("\n--------------------------------------------------------------------------------------------------------------\n")        
            output_file.write("\n Your database is at risk, follow the recommended setting to secure your database\n") 
            if not secure_auth_enabled:
                output_file.write("Secure auth should be enabled\n")
            if not enforce_gtid_enabled:
                output_file.write("Enforce gtid should be enabled\n")
            if not hashed_password:
                output_file.write("Password should be hashed and Use strong password\n")
            if privileged_users: 
                output_file.write("Please review user privileges as many users have access to full database\n")
            if unnecessary_services:
                output_file.write("Stop all the unecessary_services\n")
            
            
                   
        # Return True if any security issues were found for privileged users
        return f"Security audit details saved to {output_file_path}"

    except mysql.connector.Error as err:
        return str(err)
        

    finally:
        # Close the connection
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
            print("Connection closed.")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get MySQL details from the form
        mysql_host = request.form['host']
        mysql_user = request.form['user']
        mysql_password = request.form['password']
        mysql_db= request.form['Db']   
        output_file_path = "database_audit.txt"

        # Check database security and save results to a file for privileged users
        security_issues_found = check_database_security(mysql_host, mysql_user, mysql_password, output_file_path,mysql_db)
        result_message =  str(security_issues_found)
        try:
            if platform.system() == "Windows":
                subprocess.run(["start", "", output_file_path], check=True, shell=True)
            else:
                subprocess.run(["xdg-open", output_file_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            
    else:
        result_message = None

    return render_template('index.html', result_message=result_message)

if __name__ == '__main__':
    app.run(debug=True)
