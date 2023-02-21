# NVIP Proof-of-Concept User Interface

## Requirements

### Node.js

    - The NVIP site makes use of Angular for its functionality. Node.js is required
    in order to run Angular so it must be included in order for the project to run.
    	- Download Link: https://nodejs.org/en/download/

### Java Maven

    - Java Maven is used to compile the project with its requirements.

- Download Link: https://maven.apache.org/download.cgi

### Apache Tomcat Server

    - Tomcat 9 is currently used for its Java Web Hosting
    	- Download Link: https://tomcat.apache.org/download-90.cgi

### MySQL

    - You will need MySQL installed and an nvip database setup for the UI to recieve and grab data.
      Refer to MySQL setup in nvip_backend README to get started.

### Eclipse EE

    - Several of the development processes are made easier through the enterprise edition of
    Eclipse, although it is not needed to setup
    	- Current release: https://www.eclipse.org/downloads/packages/release/2020-03/r/eclipse-ide-enterprise-java-developers-includes-incubating-components

### Docker CLI

    - The Dockerfile provided in this folder make it easy to deploy the API locally. Get Docker here: https://docs.docker.com/get-docker/

## Deployment Steps via IDE

#### 1. Open UI project as Maven project in IDE of choice

    - Update project to import dependencies if not done automatically

#### 2. Create a Tomcat 9.0 server into your IDE.

    - (Eclipse) Click "Window" tab in the top bar.

    	- Select "Show Views". In the dropdown, select the "Servers" window and open. Should appear in the bottom part of the interface

    		- May be in "Other" if not immediately visible

    - (Eclipse) On the "Servers" window, right click and select "New" to add a new server

#### 3. Adding Apache as a Server

    - (Eclipse) Select "Apache" > "Apache Tomcat 9.0". Click "Next"

    	- If Apache option not available see "Adding Apache as a Server Option"

    	- If you selected a different version of Tomcat, select the appropriate version here

    - (Eclipse) Specify [tomcat-dir] as "Tomcat installation Directory". Click "Finish"

    	- If do not see "Tomcat installation Directory" on this screen, may have multiple servers
    	of the same version installed.

    		- Click "Back" and then look for "Add" next to "Server runtime environment" dropdown.
    		  Look for "Tomcat installation directory" and choose [tomcat-dir] as the location

    		- Click "Finish" to create the server

    - Name of the created Tomcat server will be referred to as [tomcat-server]

#### 4. (Optional) Adding JDBC Drivers into the Server

    - This is necessary in order to allow the application to connect to the database, which may be located.

    - If the database is locally hosted (i.e. within the same VM) then this step can be skipped. Local databases such as SQLite will still need to follow the steps to install the driver remotely from some application known in the server.

    - Copy the JDBC drivers (jar file) for the databases you want to connect to into [tomcat-dir]/lib

    	- SQL Server
    		- https://mvnrepository.com/artifact/com.microsoft.sqlserver/mssql-jdbc/8.2.2.jre13

    	- SQLite
    		- https://mvnrepository.com/artifact/org.xerial/sqlite-jdbc/3.31.1

    - In the [tomcat-dir], add a new directory for the database

    	- In the NVIPWeb project, locate the context.xml file (NVIPWeb > META-INF > context.xml)

    		- This file will have the directory the database is currently configured to be stored at

    			- e.g. /${catalina.base}/[database-dir]/[database-name]

    	- Create the directory, [database-dir] in the [tomcat-dir] if it does not already exist

    	- Put the database named, [database-name] inside the directory

#### Hot Deployment of Project (Development Only)

#### 5a. (Eclipse Java EE) Enabling Hot Deployment with Project Facets

    - Note: Requires "Eclipse IDE for Enterprise Developers", which is also freely available

    	- Current release: https://www.eclipse.org/downloads/packages/release/2020-03/r/eclipse-ide-enterprise-java-developers-includes-incubating-components

    - This step will enable changes to the project to be immediately deployed to the server while
    developing

    	- If publishing the application elsewhere, should follow "Create a WAR File"

    - Right-click on the project and select "Properties". Locate "Project Facets"

    - In "Project Facets", select "Dynamic Web Projects". On the right-hand side, select the
    "Runtimes" tab

    - In the "Runtimes" time, select [tomcat-server] and add a checkmark. Then click "Apply" or "Apply and Close"

    	- If [tomcat-server] is not appearing or want to add a different server, can click "New..."
    	and follow the steps from (3) to add the server

#### 6a. Locate newly created [tomcat-server] in the "Servers" window

    - (Eclipse) Right-click on [tomcat-server]. Select "Add and Remove..."

    - Add the dynamic project, "nvip_site_[version_number]" to the server. Click "Finish"

    - Start the server by right-clicking on [tomcat-server] and selecting "Start"

    - Tomcat server will now deploy project to http://localhost:8080/nvip_site/.

    	- To change the port, see "Change Deployment Port" below

## Deploying the Project from a WAR file

#### 1. (Eclipse) Create WAR file for deployment.

    - (Eclipse) Ensure the workspace is using a JDK to allowing for packaging the file into
    WAR far.

    	- See "Setting Workspace JDK"

    - (Eclipse) Locate the project in Eclipse

    - (Eclipse) Select "Run As" on the project. Select "maven clean"

    	- This will clean the target directory which will remove the previous war file.

    - (Eclipse) Select "Run As" after clean is complete again. Select "maven build..."

    - (Eclipse) In the Goals section, enter "package" and click "Apply". Then click "Run"

    	- Once completed, the war file will be placed within the target directory within the project

    	- WAR file will be referred to as [war-file]

    - (Eclipse) [Tomcat 9+ only] Return the workspace Java version to a JRE

    	- Follow the instructions for "Setting Workspace JDK". Select an available JRE
    	once reach the "Installed JREs" window.

#### 1b. (Command Line) Creating WAR file for deployment.

    - Open an command prompt/shell and navigate to the nvip_ui directory

    - Run the following command from the rrot of nvip_ui_::

    	mvn clean package

    - A WAR file will be outputted in the target directory

#### 2a. Adding the WAR file to the server manually

    - Make sure your Tomcat service is running, if not try the following:

    	- (Windows) Go to your services panel and find the service named "Apache Tomcat 9.0" and start it.

    - Locate your tomcat directory (%CATALINA_HOME% by default). Find the "webapps" directory

    - Copy the outputted WAR file to the "webapps" directory.

    - A new directory will be made to contain the contents of the WAR file

    - To test, connect to your local app via TomCat instance on a web browser (localhost:8080/<name of WAR file>)

#### 2b. Adding a WAR file to the server via Eclipse

    - (Eclipse) From Eclipse, locate the "Servers" window and find [tomcat-server]

    - (Eclipse) Right-click [tomcat-server] and select "Start" to start the server

    - (Eclipse) Check the "Console" output. If successful the project will now deploy project to http://localhost:8080/nvip_site/.

    	- To change the port, see "Change Deployment Port" below

### Deploying the Project as a Docker container

#### 1. Install Docker from https://docs.docker.com/get-docker/

#### 2. Build NVIP_API image

    $ docker build -t nvip_api .

#### 3. Run Docker Image

    $ docker run -p 8080:8080 nvip_api

#### 4. Verify Deployment

    Go to localhost:8080/nvip_ui-1.0/ to confirm API is online

## Installation & Configuration Notes

#### Adding Apache as a Server Option

    - (stub)

#### Change Deployment Port

1. (Eclipse) On "Servers" window, double-click on the name of the server you wish to change
2. (Eclipse) Under the "Ports" dropdown, select "HTTP/1.1"
   - Should currently show current port deployed at (localhost:8080 by default)
   - Change to desired port

#### Running Eclipse on VM

1. Running Eclipse from the VM requires Administrator permissions. Select "Run as administrator" in order to start Eclipse.

### (Eclipse) Setting Workspace JDK

1. Select "Window" > "Preferences" from the top navigation bar.

2. Locate "Java" and open the dropdown. Select "Installed JREs"

3. Select one of the available JDK files. The NVIP UI requires a JDK of Java 8+.

### Connecting UI to MYSQL Database

1. Be sure your NVIP database is already setup, if not, please refer to the main project README or the nvip_backend README.

2. Once your database is all set, apply your database username and password in line 5 of the context file.
   The file can be found at the location 'WebContent/META-INF/context.xml'.

### Connecting a Twitter Account for the Review Module

1. The CVE review page of the NVIP UI also allows for any reviewed CVEs to be posted on Twitter

2. To add a Twitter account for this, go to the context.xml file located in 'WebContent/META-INF/context.xml' and
   change the following values to what is applied to your Twitter account.

- consumerKey
- consumerSecret
- accessToken
- accessTokenSecret

## Troubleshooting

1. Run the TomCat server locally and test if you can access the home page (localhost:8080)

2. If not, stop the server and clean your nvip_ui project (Project -> Clean)

3. Clean your server by right clicking on the server in server view and selecting "Clean"

4. Right click on the server in server view and go to properties

5. Select "Switch Location", the location should now be specified

6. Close the window and double-click on the server in server view. Under Server Locations, select "Use Tomcat Installation"

   - If you're not able to select it, remove nvip_ui from the "Add and Remove" menu, clean the server and try again
   - Be sure to add nvip_ui back to the server once it's all set

7. Right-click on your projects pom.xml and Maven -> Update Project

8. Right click on nvip_ui and select Run As.. -> Run on Server
