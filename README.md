# Project Info:
It is a login system for Uofc students, applicants and admin.
It gives following functionalities to the users:

### Current Students:
You can view your:
- `Enrollment Info`: You can choose the semesters and view enrolled course, enroll in new course or drop the current ones.
- `Personal Info`: Can view your personal details like username, email etc.
- `Payroll Details`: You can view your payroll history, view your bank details and update them

### Applicants / ALumni:
- `View/Create Application`: View existing application, and create new application.
- `View Transcript`: View transcript of all graded courses. 
- `Personal Info`: Can view your personal details like username, email etc.

### Admin:
- `Manage courses`: Admin can view, add or remove any courses from the list.
- `Review Applications`: Admin can review any application and mark them 'Pending' / 'Approved'.


# Vulnerability:
My chosen CWEs are [CWE:89](https://cwe.mitre.org/data/definitions/89.html) and [CWE:27](https://cwe.mitre.org/data/definitions/287.html).
1. SQL Injection (CWE-89):
The vulnerability exists in the authentication function where user inputs (username/password) are directly concatenated into SQL queries without proper sanitization. For example
```
snprintf(query, sizeof(query), "SELECT * FROM users_eid WHERE eid='%s' AND password='%s'", eid, password);
```
2. Improper Authentication (CWE-287):
The authentication flow fails to properly validate user provided credentials. After querying the database, the code simply checks if any rows are returned from the database without verifying if the returned data actually matches the user's credentials.


# How to Run Vulnerability:
- Choose any type of user
- Input a valid username/eid (Given Below)
- Input `random' or '1'='1` as a password. You can change "random" to anything and this would let you login as a valid user and let you allow perform all the actions

# How to Setup:
- Setup sqlite db with command `sqlite3 uofc.db < setup.sql`
- Once command is run successfully, you should be able to see `uofc.db` in the directory
- `setup.sql` by default insert some data in the database you can view them from `setup.sql` or `uofc.db` (Also listed at the end)
- I have created `MakeFile` to create the executable or instead run this command `gcc -O2 -Wall uofcLogin.c -I/opt/saltstack/salt/include -L/opt/saltstack/salt/lib -lsqlite3 -o uofcLogin`

- Listing some user credentials here:
- Current Student:
    - username = `ebob`
    - password = `secure567`
- Current Student:
    - eID = `30048252`
    - password = `pass456`
- Admin:
    - username = `admin`
    - password = `admin123`

