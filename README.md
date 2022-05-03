This repository contains Fortinet oriented scripts designed to enhance the value of log data with registry and geolocation data.

Required Python Dependencies:
----------------------------
- xlsxwriter
- fiaclient
- requests

Setup and Configuration:
-----------------------

1) Install Docker
2) Install Docker Compose
3) Clone the FireHOL IP Aggregator repository (git clone https://github.com/spacepatcher/FireHOL-IP-Aggregator.git)
4) Navigate to the FireHOL IP Aggregator project directory and run 'docker-compose up' as the system user
5) Verify that the aggregator endpoint is running by: " curl http://container-host-addr:8000/search/ip?v=8.8.8.8 "
6) Embed the subject log file in the same directory as the ProduceReport.py script
7) Run ProduceReport.py (or ProduceReport.exe) and specify the log file when prompted. 
8) Retrieve or examine the report file in .xlsx format
