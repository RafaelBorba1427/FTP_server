#!/bin/bash
read -p "Please insert the user: " user_name
read -p "Now insert the server's IP (private) : " serv_ip
read -sp "Now insert the password: " pass
sshpass -p "$pass" ssh -X "$user_name"@"$serv_ip"
exec bash

