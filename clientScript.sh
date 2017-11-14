#!/bin/sh

# NULL 1KB WRITE
counter=0
counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

# AES128 1KB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

# aes256 1KB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1KB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1KB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

# NULL 1MB WRITE
counter=0
counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

# AES128 1MB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

# aes256 1MB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1MB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1MB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

# NULL 1GB WRITE
counter=0
counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

# AES128 1GB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

# aes256 1GB WRITE
counter=0
counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 WRITE 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py write 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

# NULL 1GB read
counter=0
counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "NULL read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 null lolsecretkey) &> resultsFinal.txt 

# AES128 1GB read
counter=0
counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes128 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes128 lolsecretkey) &> resultsFinal.txt 

# aes256 1GB read
counter=0
counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 

counter=$((counter + 1)) 
echo "aes256 read 1GB TEST: $counter" >> resultsFinal.txt
(time python3 client.py read 1GB.bin localhost:5678 aes256 lolsecretkey) &> resultsFinal.txt 
