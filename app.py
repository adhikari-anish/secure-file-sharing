from flask import Flask, render_template, session, redirect, url_for, request, flash, send_file
import os
from utils.encryption import encrypt_file, decrypt_file, encrypt_key_for_requester, decrypt_key_for_requester, generate_aes_key  # Import AES encryption functions
import tempfile
from web3 import Web3


app = Flask(__name__,  template_folder='templates')
app.secret_key = 'your_secret_key'

# Connect to local Ganache blockchain
ganache_url = "http://127.0.0.1:7545"  # Adjust if necessary
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if connected
if web3.is_connected():
    print("Connected to Ganache!")

# Replace this with the deployed contract address
contract_address = '0x84f2d7FA026bdc6d4BFBC67f0469D30346A6FE84'

# Load the contract ABI (from Truffle build)
import json
with open('truffle_project/build/contracts/FileSharing.json') as f:
    contract_json = json.load(f)
    contract_abi = contract_json['abi']

contract = web3.eth.contract(address=contract_address, abi=contract_abi)

########################################################################

# Mock users (In a real app, this should come from a database)
USERS = {
    'owner_user': {'role': 'owner', 'password': 'owner_user'},
    'requester_user': {'role': 'requester', 'password': 'requester_user'}
}
########################################################################


@app.route('/')
def index():
    # Check if user is logged in
    if 'role' in session:
        role = session['role']
        if role == 'owner':
            return redirect(url_for('owner_dashboard'))
        elif role == 'requester':
            return redirect(url_for('requester_dashboard'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Authenticate user
    if username in USERS and USERS[username]['password'] == password:
        session['role'] = USERS[username]['role']
        session['username'] = username
        
        # Redirect based on role
        if USERS[username]['role'] == 'owner':
            return redirect(url_for('owner_dashboard'))
        elif USERS[username]['role'] == 'requester':
            return redirect(url_for('requester_dashboard'))
    else:
        # If login fails, re-render login page with a message
        return render_template('login.html', message="Invalid Credentials")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# File Owner Dashboard
@app.route('/owner/dashboard')
def owner_dashboard():
    if 'role' in session and session['role'] == 'owner':
        return render_template('owner_dashboard.html')
    return redirect(url_for('index'))

# # Ensure the uploads folder exists
UPLOAD_FOLDER = './uploads'
# if not os.path.exists(UPLOAD_FOLDER):
#     os.makedirs(UPLOAD_FOLDER)

# Store encryption metadata in memory for simplicity (you can use a database)
ENCRYPTED_FILES = {
    # 'original_filename.txt': {
    #     'encrypted_filename': 'encrypted_original_filename.txt',
    #     'iv': 'iv',   # Initialization vector for AES
    #     'salt': 'salt' # Salt for AES key derivation
    # },
    # 'original_filename.txt': {
    #     'encrypted_filename': 'encrypted_original_filename.txt',
    #     'iv': 'iv',   # Initialization vector for AES
    #     'salt': 'salt' # Salt for AES key derivation
    # },
    # # Additional files can be added in the same format
}


########################################################################
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files or request.form.get('password') == '':
            flash('No file or password provided!')
            return render_template('upload.html')

        file = request.files['file']
        password = request.form['password']  # Password for AES encryption

        if file.filename == '':
            flash('No selected file')
            return render_template('upload.html')

        # Encrypt the file
        file_data = file.read()
        encrypted_data, key, iv, salt = encrypt_file(file_data, password)

        # Save the encrypted file in the 'uploads' folder
        encrypted_filename = f"encrypted_{file.filename}"
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        with open(encrypted_filepath, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Store file metadata in the dictionary
        ENCRYPTED_FILES[file.filename] = {
            'encrypted_filename': encrypted_filename,
            'iv': iv,
            'salt': salt,

        }

        # Record file on blockchain
        file_owner = web3.eth.accounts[0]  # Using first account from Ganache
        print(">>>>> ", file.filename, file_owner)
        tx_hash = contract.functions.uploadFile(file.filename).transact({'from': file_owner})
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        print(">>>> tx_receipt", tx_receipt)

        # Confirm that the file is recorded
        file_exists = contract.functions.files(file.filename).call()
        print(f"File info from blockchain: {file_exists}")

        flash('File uploaded, encrypted, and recorded on the blockchain!')
        return render_template('upload.html')

    return render_template('upload.html')

########################################################################


# Requester Dashboard
@app.route('/requester/dashboard')
def requester_dashboard():
    if 'role' in session and session['role'] == 'requester':
        return render_template('requester_dashboard.html')
    return redirect(url_for('index'))

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download_file(filename):
    if request.method == 'POST':
        password = request.form['password']  # Password to decrypt the file

        if filename not in ENCRYPTED_FILES:
            flash('File not found!')
            return redirect(url_for('list_files'))

        # Load the encrypted file from the uploads folder
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, ENCRYPTED_FILES[filename]['encrypted_filename'])
        if not os.path.exists(encrypted_filepath):
            flash('Encrypted file not found!')
            return redirect(url_for('list_files'))

        with open(encrypted_filepath, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Get the encryption metadata
        iv = ENCRYPTED_FILES[filename]['iv']
        salt = ENCRYPTED_FILES[filename]['salt']

        # Decrypt the file
        try:
            decrypted_data = decrypt_file(encrypted_data, password, iv, salt)
        except Exception as e:
            flash('Decryption failed! Invalid password or corrupted file.')
            return redirect(url_for('list_files'))

        # Save the decrypted file temporarily using a tempfile
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(decrypted_data)
        temp_file.flush()  # Make sure all data is written to disk
        temp_file_name = temp_file.name
        temp_file.close()

        # Send the file as a downloadable attachment
        response = send_file(temp_file_name, as_attachment=True, download_name=filename)

        # Clean up the temporary file after sending it
        os.remove(temp_file_name)

        return response

    return render_template('download.html', filename=filename)

@app.route('/files')
def list_files():
    files_in_uploads = os.listdir(UPLOAD_FOLDER)

    files_metadata = []
    for filename, details in ENCRYPTED_FILES.items():
        if details['encrypted_filename'] in files_in_uploads:
            try:
                access_info = contract.functions.accessRequests(filename).call()

                # Query the blockchain to check if access is approved for the requester
                access_approved = contract.functions.isAccessApproved(filename).call()
            except Exception as e:
                access_approved = False  # If there's an error, assume access is not approved

            # Add file metadata and access approval status to the list
            files_metadata.append({
                'original_filename': filename,
                'encrypted_filename': details['encrypted_filename'],
                'owner': details.get('owner', 'Unknown'),  # Store the owner or set to 'Unknown'
                'access_approved': access_approved,  # Access status from blockchain
                 'request_exists': access_info[2],
                 'approved': access_info[1],
            })

    # Render the file list with access approval status
    return render_template('file_list.html', files=files_metadata)




@app.route('/request_access/<filename>', methods=['POST'])
def request_access(filename):
    if 'role' in session and session['role'] == 'requester':
        try:
            # Check if the file exists on the blockchain
            file_exists = contract.functions.files(filename).call()
            if not file_exists:
                flash(f"File '{filename}' does not exist on the blockchain.")
                return redirect(url_for('list_files'))

            # Retrieve the requester's public key from the form
            public_key = request.form['public_key']

            # Transact the access request
            user_address = web3.eth.accounts[1]  # Assuming the requester's account
            tx_hash = contract.functions.requestAccess(filename, public_key).transact({'from': user_address})
            web3.eth.wait_for_transaction_receipt(tx_hash)

            flash(f"Access request for '{filename}' has been submitted.")
        except Exception as e:
            flash(f"Error requesting access: {str(e)}")
    
    return redirect(url_for('list_files'))




@app.route('/approve_access/<filename>', methods=['POST'])
def approve_access(filename):
    if 'role' in session and session['role'] == 'owner':
        try:
            # Owner must provide the password again when approving access
            aes_key = request.form['file_password']

            # Retrieve the AES key (for the file) and other metadata
            # aes_key = generate_aes_key(file_password, ENCRYPTED_FILES[filename]['salt'])
            iv = ENCRYPTED_FILES[filename]['iv']



            # Get the access request information from the blockchain
            access_info = contract.functions.accessRequests(filename).call()

            print(access_info)

            # Access the tuple elements using integer indices
            requester_address = access_info[0]
            approved = access_info[1]
            exists = access_info[2]
            public_key = access_info[3]
            encrypted_key = access_info[4]

            if not exists:
                flash(f"Access request for {filename} does not exist.")
                return redirect(url_for('list_files'))

            # Encrypt the AES key with the requester's public key
            encrypted_aes_key = encrypt_key_for_requester(aes_key, public_key)

            # Approve access and store the encrypted AES key on the blockchain
            owner_address = web3.eth.accounts[0]
            tx_hash = contract.functions.approveAccessWithKey(filename, encrypted_aes_key).transact({'from': owner_address})
            web3.eth.wait_for_transaction_receipt(tx_hash)

            flash(f'Access for {filename} has been approved with encrypted AES key.')

        except Exception as e:
            flash(f'Error approving access: {str(e)}')
    else:
        flash('You are not authorized to approve access.')

    return redirect(url_for('list_files'))




@app.route('/file_status/<filename>', methods=['GET'])
def file_status(filename):
    try:
        # Check if access is approved
        access_approved = contract.functions.isAccessApproved(filename).call()
        if access_approved:
            return f"Access to {filename} has been approved."
        else:
            return f"Access to {filename} is pending."
    except Exception as e:
        return f"Error retrieving status: {str(e)}"



# @app.route('/decrypt_file/<filename>', methods=['POST'])
# def decrypt_file_route(filename):
#     if 'role' in session and session['role'] == 'requester':
#         try:
#             # Requester's private key is submitted via a form
#             requester_private_key = request.form['private_key']
            
#             # Check if access is approved
#             access_info = contract.functions.accessRequests(filename).call()

#             if access_info[1]:  # Check if access is approved using integer index
#                 # Retrieve the encrypted AES key from the blockchain
#                 encrypted_aes_key = access_info[4]  # Use index to retrieve encryptedKey

#                 # Decrypt the AES key using the requester's private key
#                 decrypted_aes_key = decrypt_key_for_requester(encrypted_aes_key, requester_private_key)

#                 # Retrieve the file metadata from ENCRYPTED_FILES
#                 file_info = ENCRYPTED_FILES.get(filename)
#                 if not file_info:
#                     flash('File metadata not found!')
#                     return redirect(url_for('list_files'))

#                 # Retrieve the encrypted file, IV, and salt from the stored metadata
#                 encrypted_filename = file_info['encrypted_filename']
#                 iv = file_info['iv']
#                 salt = file_info['salt']

#                 # Read the encrypted file
#                 encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
#                 with open(encrypted_filepath, 'rb') as encrypted_file:
#                     encrypted_data = encrypted_file.read()

#                 # Decrypt the file using the decrypted AES key, IV, and salt
#                 decrypted_data = decrypt_file(encrypted_data, decrypted_aes_key, iv, salt)

#                 # Serve the decrypted file to the requester (this is just an example, you may want to handle it differently)
#                 return decrypted_data
#             else:
#                 flash('Access has not been approved yet.')
#         except Exception as e:
#             flash(f'Error decrypting file: {str(e)}')

#     return redirect(url_for('list_files'))



@app.route('/decrypt_file/<filename>', methods=['POST'])
def decrypt_file_route(filename):
    if 'role' in session and session['role'] == 'requester':
        try:
            # Requester's private key is submitted via a form
            requester_private_key = request.form['private_key']

            # Check if access is approved
            access_info = contract.functions.accessRequests(filename).call()

            if access_info[1]:  # Check if access is approved using integer index
                # Retrieve the encrypted AES key from the blockchain
                encrypted_aes_key = access_info[4]  # Use index to retrieve encryptedKey

                # Decrypt the AES key using the requester's private key
                decrypted_aes_key = decrypt_key_for_requester(encrypted_aes_key, requester_private_key)

                print("===> decrypted_aes_key", decrypted_aes_key)


                # Retrieve the file metadata (IV and salt) from ENCRYPTED_FILES
                file_info = ENCRYPTED_FILES.get(filename)
                if not file_info:
                    flash('File metadata not found!')
                    return redirect(url_for('list_files'))

                # Access the dictionary keys correctly
                encrypted_filename = file_info['encrypted_filename']
                iv = file_info['iv']
                salt = file_info['salt']

                # Read the encrypted file from the uploads directory
                encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
                with open(encrypted_filepath, 'rb') as encrypted_file:
                    encrypted_data = encrypted_file.read()

                # Decrypt the file using the decrypted AES key, IV, and salt
                decrypted_data = decrypt_file(encrypted_data, decrypted_aes_key, iv, salt)

                # Save the decrypted file temporarily using a tempfile
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                temp_file.write(decrypted_data)
                temp_file.flush()  # Make sure all data is written to disk
                temp_file_name = temp_file.name
                temp_file.close()

                # Send the file as a downloadable attachment
                response = send_file(temp_file_name, as_attachment=True, download_name=f'decrypted_{filename}')

                # Optionally, clean up the temporary file after download
                @response.call_on_close
                def cleanup():
                    os.remove(temp_file_name)

                return response
            else:
                flash('Access has not been approved yet.')
        except Exception as e:
            flash(f'Error decrypting file: {str(e)}')

    return redirect(url_for('list_files'))


if __name__ == '__main__':
    app.run(debug=True)