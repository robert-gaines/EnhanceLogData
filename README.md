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
5) Verify that the aggregator endpoint is running by: " curl http://<container-host-addr>:8000/search/ip?v=8.8.8.8 "
6) Navigate to the GeoIPData directory and run "CreateAndPopulateGeoIPDB.py"
   Note: this will take a while, but the offline query option is less expensive than other API options on the web.
7) The "CreateAndPopulateGeoIPDB.py" script will return an 'ip_geodata.db' file, move this database to the same directory as the ProduceReport.py script
8) Embed the subject log file in the same directory as the ProduceReport.py script
9) Run ProduceReport.py and specify the log file when prompted. 
10)Retrieve or examine the report file in .xlsx format
