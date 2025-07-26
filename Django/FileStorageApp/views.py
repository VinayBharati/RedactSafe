from django.views.decorators.csrf import csrf_exempt
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
import datetime
import ipfshttpclient
import os
import json
from web3 import Web3, HTTPProvider
from django.core.files.storage import FileSystemStorage
import pickle
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import time
import numpy as np
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import timeit
from hashlib import sha256
import matplotlib.pyplot as plt
import io
import base64
import requests
import matplotlib
import re
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password


matplotlib.use("Agg")  # Use non-interactive backend for web servers

# Initialize globals to avoid NameError
enc_time = 0
dec_time = 0
extension_enc_time = 0

def ipfs_version():
    response=requests.post('http://127.0.0.1:5002/api/v0/version')
    return response.json()
print(ipfs_version())
# client=ipfshttpclient.connect(addr='/ip4/127.0.0.1/tcp/5002/http',session=True)
global details, username


#function to generate public and private keys for Chebyshev polynomial algorithm
def ChebyshevGenerateKeys():
    if os.path.exists("pvt.key"):
        with open("pvt.key", 'rb') as f:
            private_key = f.read()
        f.close()
        with open("pri.key", 'rb') as f:
            public_key = f.read()
        f.close()
        private_key = private_key.decode()
        public_key = public_key.decode()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()  # hex string
        public_key = secret_key.public_key.to_hex()
        with open("pvt.key", 'wb') as f:
            f.write(private_key.encode())
        f.close()
        with open("pri.key", 'wb') as f:
            f.write(public_key.encode())
        f.close()
    return private_key, public_key

#Chebyshev will encrypt data using plain text adn public key
def ChebyshevEncrypt(plainText, public_key):
    cpabe_encrypt = encrypt(public_key, plainText)
    return cpabe_encrypt

#Chebyshev will decrypt data using private key and encrypted text
def ChebyshevDecrypt(encrypt, private_key):
    cpabe_decrypt = decrypt(private_key, encrypt)
    return cpabe_decrypt
one={
    'from':"0xeF6b97B1c92Db01bFBE8181AFa2099Cc94259aa5"
}
def readDetails(contract_type):
    global details
    details = ""
    print(contract_type+"======================")
    blockchain_address = 'http://127.0.0.1:7545' #Blokchain connection IP
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'SmartContract.json' #Blockchain SmartContract calling code
    deployed_contract_address = '0x3fcea4AfFF4021bf98f7ac9509b469Da5B7e0Feb' #hash address to access Shared Data contract
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi) #now calling contract to access data
    if contract_type == 'signup':
        details = contract.functions.getSignup().call(one)
        print(details,"lfdhlkdsfkldfj")
    if contract_type == 'attribute':
        details = contract.functions.getAccess().call(one)
    if contract_type == 'permission':
        details = contract.functions.getPermission().call(one)      
    print(details)    

def saveDataBlockChain(currentData, contract_type):
    global details
    global contract
    details = ""
    blockchain_address = 'http://127.0.0.1:7545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'SmartContract.json' #Blockchain contract file
    deployed_contract_address = '0x3fcea4AfFF4021bf98f7ac9509b469Da5B7e0Feb' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    readDetails(contract_type)
    if contract_type == 'signup':
        details+=currentData
        msg = contract.functions.setSignup(details).transact(one)
       
    if contract_type == 'attribute':
        details+=currentData
        msg = contract.functions.setAccess(details).transact(one)
     
    if contract_type == 'permission':
        details+=currentData
        msg = contract.functions.setPermission(details).transact(one)
 

def updateDataBlockChain(currentData):
    blockchain_address = 'http://127.0.0.1:7545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'SmartContract.json' #SmartContract file
    deployed_contract_address = '0x3fcea4AfFF4021bf98f7ac9509b469Da5B7e0Feb' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    msg = contract.functions.setPermission(currentData).transact(one)

def index(request):
    if request.method == 'GET':
       return render(request, 'Dashboard.html', {})

def Login(request):
    if request.method == 'GET':
       return render(request, 'Login.html', {})

def Signup(request):
    if request.method == 'GET':
       return render(request, 'Signup.html', {})

def SharedData(request):
    if request.method == 'GET':
       global username       
       return render(request, 'SharedData.html', {})

def DownloadFileDataRequest(request):
    if request.method == 'GET':
        global dec_time
        hashcode = request.GET.get('hash', False)
        filename = request.GET.get('file', False)
        access = request.GET.get('access', False)
        readDetails('attribute')
        arr = details.split("\n")
        start_times = time.time()
        decrypted = None
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            share_user = array[6].split(",")
            if array[0] == 'post' and array[3] == hashcode:
                private_key, public_key = ChebyshevGenerateKeys()
                content=requests.post('http://127.0.0.1:5002/api/v0/cat',params={'arg':array[3]})
                decrypted = content.content
                break
            
        end_times = time.time()
        dec_time = end_times - start_times
        if access in ['Private', 'Public', 'download', 'read']:
            response = HttpResponse(decrypted, content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{filename}"'
            return response
        else:
            return HttpResponse("Access denied or invalid request.", status=403)
            

from django.contrib import messages
from django.shortcuts import redirect

def Permission(request):
    if request.method == 'GET':
        global username
        requester = request.GET.get('requester', False)
        owner = request.GET.get('owner', False)
        filename = request.GET.get('filename', False)
        permission = request.GET.get('permission', False)
        readDetails('permission')
        arr = details.split("\n")
        temp = ""
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[0] == requester and array[1] == owner and array[2] == filename:
                selected = f"{array[0]}#{array[1]}#{array[2]}#{array[3]}#{array[4]}#{permission}\n"
                temp += selected
            else:
                temp += arr[i] + "\n"
        updateDataBlockChain(temp)

        messages.success(request, f"Permission for <strong>{filename}</strong> set to <strong>{permission}</strong> for requester <strong>{requester}</strong>.")
        return redirect('ViewRequest')  # Use your URL name here

from django.shortcuts import render
# from django.contrib import messages  # Already imported in Permission view

def ViewRequest(request):
    if request.method == 'GET':
        global username
        strdata = """
        <table class="min-w-full divide-y divide-gray-300 text-sm text-left text-gray-900 border border-gray-200">
          <thead class="bg-gray-100">
            <tr>
              <th class="px-4 py-2 border border-black">Requester Name</th>
              <th class="px-4 py-2 border border-black">Owner Name</th>
              <th class="px-4 py-2 border border-black">Filename</th>
              <th class="px-4 py-2 border border-black">Hashcode</th>
              <th class="px-4 py-2 border border-black">Access Control</th>
              <th class="px-4 py-2 border border-black">Permissions</th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">
        """

        readDetails('permission')
        arr = details.split("\n")

        for i in range(len(arr) - 1):
            array = arr[i].split("#")
            if array[1] == username and array[5] == "Pending":
                strdata += f"""
                <tr>
                  <td class="px-4 py-2 border border-black">{array[0]}</td>
                  <td class="px-4 py-2 border border-black">{array[1]}</td>
                  <td class="px-4 py-2 border border-black">{array[2]}</td>
                  <td class="px-4 py-2 border break-words border-black">{array[3]}</td>
                  <td class="px-4 py-2 border border-black">{array[4]}</td>
                  <td class="px-4 py-2 border space-x-2 border-black">
                    <a href='Permission?requester={array[0]}&owner={array[1]}&filename={array[2]}&permission=read' class='text-green-600 hover:underline'>Read</a>
                    <a href='Permission?requester={array[0]}&owner={array[1]}&filename={array[2]}&permission=download' class='text-blue-600 hover:underline'>Download</a>
                  </td>
                </tr>
                """

        strdata += "</tbody></table>"

        context = {'data': strdata}
        return render(request, 'ViewRequest.html', context)

        
from django.contrib import messages
from django.shortcuts import render, redirect

def SendRequest(request):
    if request.method == 'GET':
        global username
        owner = request.GET.get('owner', False)
        hashcode = request.GET.get('hash', False)
        filename = request.GET.get('file', False)
        access = request.GET.get('access', False)
        readDetails('permission')
        arr = details.split("\n")
        status = None
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[0] == username and array[1] == owner and array[2] == filename:
                status = f"Your request for <b>{filename}</b> has already been posted to owner <b>{array[1]}</b>."
                break
        if status is None:
            data = f"{username}#{owner}#{filename}#{hashcode}#{access}#Pending\n"
            saveDataBlockChain(data, "permission")
            status = f"<b>Request sent!</b> The owner <b>{owner}</b> will be notified."
        # Use Django messages for modern feedback
        messages.info(request, status)
        return redirect('ViewSharedMessages')  # Use your URL name here
            

def getPermission(username, owner, filename):
    permission = "none"
    readDetails('permission')
    arr = details.split("\n")
    for i in range(len(arr)-1):
        array = arr[i].split("#")
        if array[0] == username and array[1] == owner and array[2] == filename:
            if array[5] == 'download':
                permission = "download"
                break
            if array[5] == 'read':
                permission = "read"
                break
    return permission    

def ViewSharedMessages(request):
    if request.method == 'GET':
        global enc_time, dec_time, username
        dec_time = 0
        table_rows = []

        readDetails('attribute')
        rows = details.strip().split("\n")

        start_time = time.time()
        for row in rows:
            fields = row.split("#")
            if len(fields) < 7 or fields[0] != 'post':
                continue

            owner, message, ipfs_hash, shared_dt, filename, access = fields[1:7]
            action = ""

            # Access control logic
            if (access in ['Private', 'Public']) and owner == username:
                action = f'<a href="DownloadFileDataRequest?hash={ipfs_hash}&file={filename}&access={access}" class="text-green-600 underline">Download File</a>'
            elif access == 'Public' and owner != username:
                action = f'<a href="DownloadFileDataRequest?hash={ipfs_hash}&file={filename}&access={access}" class="text-green-600 underline">Download File</a>'
            elif access == 'Private' and owner != username:
                permission = getPermission(username, owner, filename)
                if permission == "none":
                    action = f'<a href="SendRequest?owner={owner}&hash={ipfs_hash}&file={filename}&access={access}" class="text-green-600 underline">Send Request</a>'
                elif permission == "download":
                    action = f'<a href="DownloadFileDataRequest?hash={ipfs_hash}&file={filename}&access=download" class="text-green-600 underline">Download File</a>'
                elif permission == "read":
                    action = f'<a href="DownloadFileDataRequest?hash={ipfs_hash}&file={filename}&access=read" class="text-green-600 underline">Read File</a>'

            row_html = f'''
                <tr class="hover:bg-gray-50">
                    <td class="border border-black px-4 py-2">{owner}</td>
                    <td class="border border-black px-4 py-2">{message}</td>
                    <td class="border border-black px-4 py-2 break-all text-sm">{ipfs_hash}</td>
                    <td class="border border-black px-4 py-2">{shared_dt}</td>
                    <td class="border border-black px-4 py-2">{filename}</td>
                    <td class="border border-black px-4 py-2">{access}</td>
                    <td class="border border-black px-4 py-2">{action}</td>
                </tr>
            '''
            table_rows.append(row_html)

        end_time = time.time()
        dec_time = end_time - start_time

        table_html = f'''
        <table class="min-w-full border border-black border-collapse bg-white shadow-lg">
          <thead class="bg-gray-100">
            <tr>
              <th class="border border-black px-4 py-2 text-gray-900">Data Owner</th>
              <th class="border border-black px-4 py-2 text-gray-900">Shared Message</th>
              <th class="border border-black px-4 py-2 text-gray-900">IPFS File Address</th>
              <th class="border border-black px-4 py-2 text-gray-900">Shared Date/Time</th>
              <th class="border border-black px-4 py-2 text-gray-900">Shared File Name</th>
              <th class="border border-black px-4 py-2 text-gray-900">Access Control</th>
              <th class="border border-black px-4 py-2 text-gray-900">Download File</th>
            </tr>
          </thead>
          <tbody>
            {''.join(table_rows)}
          </tbody>
        </table>
        '''

        context = {'data': table_html}
        return render(request, 'ViewSharedMessages.html', context)
         


def LoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', '').strip()
        password = request.POST.get('t2', '').strip()
        readDetails('signup')
        arr = details.strip().split("\n")
        
        for line in arr:
            if not line.startswith("signup#"):
                continue
            array = line.split("#")
            saved_username = array[1]
            hashed_password = array[2]

            if saved_username == username and check_password(password, hashed_password):
                with open('session.txt', 'w') as file:
                    file.write(username)
                return redirect('Dashboard')  # ✅ Login success

        # ❌ If no match found
        context = {
            'data': 'Invalid username or password.',
            'old_values': {
                't1': username
            }
        }
        return render(request, 'Login.html', context)

import time
import timeit
import datetime
import pickle
import requests
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from django.shortcuts import render, redirect
from django.contrib import messages

def human_readable_size(size, decimal_places=2):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0 or unit == 'TB':
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

def SharedDataAction(request):
    if request.method == 'POST':
        global enc_time, username, extension_enc_time
        post_message = request.POST.get('t1', False)
        access = request.POST.get('t3')
        filename = request.FILES['t2'].name
        start = time.time()
        myfile = request.FILES['t2'].read()
        noOne = request.FILES['t2']
        myfile = pickle.dumps(myfile)
        private_key, public_key = ChebyshevGenerateKeys()
        cheb_encrypt = ChebyshevEncrypt(myfile, public_key)
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        user = username
        file = {'file': (filename, myfile, noOne.content_type)}
        content = requests.post('http://127.0.0.1:5002/api/v0/add', files=file)
        hash = content.json()
        data = (
            "post#" + user + "#" + post_message + "#" + str(hash['Hash']) +
            "#" + str(current_time) + "#" + filename + "#" + access + "\n"
        )
        end = time.time()
        enc_time = end - start

        start = timeit.default_timer()
        key = get_random_bytes(32)
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(myfile)
        end = timeit.default_timer()
        extension_enc_time = end - start
        saveDataBlockChain(data, "attribute")

        # Calculate sizes
        size_bytes = noOne.size
        size_human = human_readable_size(size_bytes)

        # Use Django's messages framework for feedback
        messages.success(
            request,
            f"<strong>Success!</strong> File shared and saved successfully.<br>"
            f"<ul class='text-xs mt-2 list-disc pl-5'>"
            f"<li><strong>File:</strong> {filename}</li>"
            f"<li><strong>IPFS Hash:</strong> {hash['Hash']}</li>"
            f"<li><strong>Size:</strong> {size_bytes} bytes ({size_human})</li>"
            f"</ul>"
        )
        return redirect('SharedDataAction')  # Use your URL name here

    # GET request: just show the form, no message unless redirected
    return render(request, 'SharedData.html')

def SignupAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', '').strip()
        password = request.POST.get('t2', '').strip()
        contact = request.POST.get('t3', '').strip()
        email = request.POST.get('t5', '').strip()
        address = request.POST.get('t6', '').strip()

        # ✅ Regex patterns
        username_regex = re.compile(r'^[a-zA-Z0-9_]{4,20}$')
        password_regex = re.compile(r'^.{6,}$')  # ✅ Only minimum 6 characters
        contact_regex = re.compile(r'^[6-9]\d{9}$')
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|in|org|net)$')

        # 🔎 Validation errors dict
        form_errors = {}

        if not username or not username_regex.match(username):
            form_errors["username"] = "Username must be 4–20 characters and alphanumeric."

        if not password or not password_regex.match(password):
            form_errors["password"] = "Password must be at least 6 characters long."

        if not contact or not contact_regex.match(contact):
            form_errors["contact"] = "Invalid contact number. Must start with 6–9 and be 10 digits."

        if not email or not email_regex.match(email):
            form_errors["email"] = "Invalid email address."

        if not address:
            form_errors["address"] = "Address is required."

        # 🔁 Check for duplicate usernames
        readDetails('signup')  # reads into global `details`
        user_exists = any(
            line.split("#")[1] == username
            for line in details.strip().split("\n")
            if line.startswith("signup#")
        )
        if user_exists:
            form_errors["username"] = f"Username '{username}' already exists."

        if form_errors:
            context = {
                "form_errors": form_errors,
                "old_values": {
                    "t1": username,
                    "t3": contact,
                    "t5": email,
                    "t6": address,
                }
            }
            return render(request, 'Signup.html', context)

        # ✅ Hash password
        hashed_password = make_password(password)

        # ✅ Store user data
        user_data = f"signup#{username}#{hashed_password}#{contact}#{email}#{address}\n"
        saveDataBlockChain(user_data, "signup")

        return redirect('Login')


def Graph(request):
    global username
    global enc_time, dec_time, extension_enc_time
    height = [enc_time, dec_time, extension_enc_time]
    bars = ('ABE Communication Overhead', 'Propose Communication Overhead', 'Extension CHA CHA Encryption')
    y_pos = np.arange(len(bars))
    plt.figure(figsize=(8, 5))
    plt.bar(y_pos, height, color=['#f87171', '#60a5fa', '#34d399'])
    plt.xticks(y_pos, bars, rotation=15)
    plt.title("Communication Overhead Graph")
    plt.ylabel("Time (s)")
    plt.tight_layout()

    # Save plot to PNG in memory
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()

    context = {
        "username": username,
        "image_base64": image_base64,
    }
    return render(request, 'communication_graph.html', context)


from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from urllib.parse import urlencode

@csrf_exempt
def redact_document(request):
    if request.method == 'POST' and request.FILES.get('document'):
        uploaded_file = request.FILES['document']
        files = {
            'files': (uploaded_file.name, uploaded_file.read(), uploaded_file.content_type)
        }
        data = {
            'piiOptions': '{"person": true, "address": true, "aadhar": true, "pan": true, "dob": true, "dl": true, "voter": true}'
        }

        try:
            resp = requests.post('http://127.0.0.1:5000/upload', files=files, data=data)
            if resp.status_code == 200:
                processed = resp.json()['processedFiles'][0]
                download_url = processed.get('download_url')
                filename = processed.get('filename')
                preview_url = processed.get('preview_url') or (f"http://127.0.0.1:5000/preview/{filename}" if filename else None)
                # Redirect with parameters (safe for GET)
                params = urlencode({
                    'download_url': download_url or '',
                    'preview_url': preview_url or '',
                    'filename': filename or ''
                })
                return redirect(f"{reverse('redact_document')}?{params}")
            else:
                messages.error(request, f"Redaction failed: {resp.text}")
                return redirect('redact_document')
        except Exception as e:
            messages.error(request, f"Error contacting redaction service: {e}")
            return redirect('redact_document')

    # GET request: show form, and if params exist, show result
    download_url = request.GET.get('download_url')
    preview_url = request.GET.get('preview_url')
    filename = request.GET.get('filename')
    return render(
        request,
        'redact_form.html',
        {
            'download_url': download_url,
            'preview_url': preview_url,
            'filename': filename,
        }
    )
