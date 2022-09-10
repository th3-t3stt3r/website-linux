#!/bin/bash
 

sudo apt-get update && sudo apt-get upgrade -y

aptDepends=( 
               python3-pip 
               python3.10-venv
               auditd
           )

pipDepends=(
               colorama==0.4.5
               cryptography==38.0.1
               psutil==5.9.1
               pyfiglet==0.8.post1
               termcolor==1.1.0
               watchdog==2.1.9
           )
sudo apt-get install -y "${aptDepends[@]}" && sudo pip3 install -y "${pipDepends[@]}"