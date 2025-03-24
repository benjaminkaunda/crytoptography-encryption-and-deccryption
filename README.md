First run the keygen.py file to generate the public and private key
results are stored in the .pem files in the key folder

Next run the encryption.py to encrypt data using a function stored in the utils.py file
Message to be encrypted is in line 11 in encryption.py file. You can change the message but ensure its not too long since rsa encryption takes a lot of time
encrypted data is stored in the encrypted data.txt file

finally run the comparison.py to compare rsa and ecc performance. Results are stored in the performance.txt file


ensure to install necessary libraries , they are in the requirements.txt file .