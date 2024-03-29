# HealthChecker
Spiceworks - Health Checker Assignment


## Task Description
- A web service that receives thousands of requests per second
- You own a web application that receives thousands of requests per second
- Each web request is evaluated concurrently
- The application depends on several external resources
- Each of those resources might be in a healthy or unhealthy state
- Each resource will be monitored (polled) at different intervals in independent threads
- Assume the health of each resource will be random and change several times throughout the life of the application
- The health of each resource will be reported to a central `HealthAggregator` using the method `SetResource`—described below—and will contain the most recent health status for a single resource
- On each request to the main app, one of the steps to perform is call `HealthAggregator.IsHealthy()` to determine the overall health of the application
- If any one of the resources is unhealthy, your web application will respond to the web request with a 5XX code
- Only if all resources are healthy will the response code be a 2XX


## Tech stack
- Language:     **Python**
- Web Service:  **Flask**
- ORM:          **Flask SQLAlchemy**
- Database:     **SQLite**
- Encryption:   **AES with RSA keys**
- Encoding:     **SHA512**
- Communications:
    - Windows:     **PowerShell Remoting**
        PowerShell version should be 4.0 and above
    - UNIX:        **SSH using Paramiko**


## Design
Upon launch of the WebService, we first check if the database exists or not.
If the database does not exists, we create, and add the **User** and **Resource** tables.
We then check if the RSA private and public keys files exists or not.

For each resource, we create an object of the **Resource** class, which executes the commands on the remote machine to get the details of the machine, and to check if the resource is healthy or not.

The user table is initialized with one User in the beginning, which can perform all operations.

    Username:   SpiceWorks
    Password:   HealthChecker


### Database
We are using SQLite database for this prototype.

The database has the following tables:

- **User**
    Table to store information related to the users which are allowed to perform advanced operations

- **Resource**
    Table to store information related to the resources which needs to be monitored


#### User Table
User table stores the **username**, **password**, and a special value **salt**.

The password is one way encrypted (encoded) for security purposes.

For authentication, we use the value of **salt** for the given username, and the password that the user gave, and check if the final value matches the value stored in the table.


#### Resource Table
The Resource table stores the **hostname**, **username**, **password**, and **interval** value of the resource.

Interval value is set default to 60 (in seconds).

Resource password is encrypted using AES cipher and RSA keys.


### Endpoints
All the endpoints and their info can be retrieved by calling the **/Routes** or **/routes** endpoint.


## Usage

To launch the webservice, launch command prompt as **Administrator** from the root directory and run:

    >>> python src
        OR
    >>> python src\app.py


## Steps to test the webservice

1. Execute the steps under the Usage section above
1. Open Postman
1. Call **/Login** with the credentials shared under Design section
1. Copy the token and pass it under headers for subsequent API calls
1. Call **/Resource** to add a new Resource
1. **/IsHealthy** to check the service health
    -   Returns HTTP Status **200**, if all the resources are healthy
    -   Returns HTTP Status **503**, if any of the resource is unhealthy

Other endpoints and their details can be retrieved using the info from **Endpoints** section above.

## Pending items

Due to limited time, I could only test it out manually, but could not write any Unit Tests.


## Changelog
- Get and store the **reason** for down state of each resource using the Resource class, and store the info in Health Aggregator service
- Safe close all threads for Health Aggregator cleanup
- Added Endpoint **GET    -   /ResourceState**, to get the list of resources, their health state, and reason if they are down
- Added Endpoint **POST   -   /Reset**, to reset the Health Aggregator service, and initiate fresh connection to all resources
- Added **tests** for the application
