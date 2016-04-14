# Infection-Proxy Detector
Automated detection of infection proxies based on statistical analysis.

### Getting started
There are only a few dependencies. These packets are needed (Ubuntu example):
```
sudo apt-get install python-dev python-pip libmysqlclient-dev -y
sudo pip install statistics
```

### Run the infection-proxy detector
As we use raw sockets, sudo is required. 
```
sudo python proxy_detect.py -i eth0 -p tcp
```
