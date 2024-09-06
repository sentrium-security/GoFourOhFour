# GoFourOhFour

## Description
*GoFourOhFour* is a lightweight, portable webserver developed using Golang.

 We developed this small and simple app to tackle some challenges when having to transfer files to / from (in particular) Windows devices. For example, devices that have restrictions (such as USB / SMB etc.). 

Currently it supports;

- File upload / download with basic web UI
- Ability to send text to the server to retrieve
- SSL (see usage)
- Authentication (see usage)


## Installation
No installation is required. Download one of the releases (currently Windows, Linux and MacOS builds are available) and execute. If you wish to make changes and build new binaries, you will need to download [Go](https://go.dev/dl/).

You can then run and test the Go package with:

`go run main.go`

To build the package, run the following example:

`go build -o GoFourOhFour.exe main.go`

## Usage

Simply open a terminal and execute the GoFourOhFour executable. Possible options and their default settings are shown below. 

```
 Usage of GoFourOhFour:
  -auth
        Only disable on secure networks! (default true)
  -path string
        Path to the folder to serve. Defaults to current directory (default ".")
  -port int
        Port to listen on. (default 8080)
  -ssl
        Enable SSL. Requires "go.crt" and "go.key" files
  -username string
        The username for authentication. (default "nimda")
```

## Options

### Auth

If you're on a secure network, you can disable auth to access the webserver unauthenticated.

### Path
The path is the directory to serve files from. By default it will serve files in the directory the executable is started from, this is also where files will be uploaded. Example of non-default `-path "c:\temp"`

### Port

The port option allows you to set a port should the default conflict with another service (Burp etc.)
Example of non-default `-port 9090`. In SSL mode, it will default to 443 (https://).

### SSL
To enable SSL, you will need to create your own go.crt and go.key files and have them in the same directory that the server is started. 
You must then pass the flag `-ssl=true` to enable. 

The following openssl command may be used to get you started.

`sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout go.key -out go.crt`

### Username
The username can be set to whatever you want but defaults to "nimda" if not set.

## Features

When executed, it provides you with an example curl command to send a file to the server, all you will need to do is replace "filename.txt" with the file you wish to upload. The command includes the -k option for curl when started in SSL mode, this ensures it ignores the certificate error.

```
### WARNING FILES WILL BE EXPOSED / UPLOADED TO DIRECTORY: . ###
---------------------------------------------------------------------
The password for web login is FfwtJylKRm75Rl
curl -H "Authorization: Basic bmltZGE6RmZ3dEp5bEtSbTc1Umw=" -F file=@filename.txt http://10.0.1.160:8080/upload
curl -H "Authorization: Basic bmltZGE6RmZ3dEp5bEtSbTc1Umw=" http://10.0.1.160:8080/download/filename.txt
Enable SSL with -ssl=true (requires a "go.crt" and "go.key" file)
---------------------------------------------------------------------
Starting server on port 8080
Starting Ticker...Mon Feb 20 16:09:14 GMT 2023
```
SSL mode:

```
### WARNING FILES WILL BE EXPOSED / UPLOADED TO DIRECTORY: . ###
---------------------------------------------------------------------
The password for web login is h6SsiUrzIjMRR2
curl -k -H "Authorization: Basic bmltZGE6aDZTc2lVcnpJak1SUjI=" -F file=@filename.txt https://10.0.1.160/upload
curl -k -H "Authorization: Basic bmltZGE6aDZTc2lVcnpJak1SUjI=" https://10.0.1.160/download/filename.txt
---------------------------------------------------------------------
Starting server on port 443
Starting Ticker...Mon Feb 20 16:11:06 GMT 2023
```

The password (random 14 characters) is only for that instance of the server, once you stop and start it, it will generate a new password which will be required to authenticate again.

The server will close down and the program will terminate after ~2mins of inactivity (no requests) to reduce any unwanted exposure of files served in the `-path`.

## Support / Contributions
Raise any issues in this repository and we will aim to resolve them when we can. Contributions are welcome, we intended this to be lightweight and portable using only Go standard libraries.

## Authors and acknowledgment
[Sentrium Security](https://www.sentrium.co.uk)

This tool was developed inhouse for our own purposes and we have decided to release it publicly. It was not developed by a professional Go developer, just a typical user that requires tools to complete tasks easily and does their best with StackOverflow to make a such a tool :). It does not provide the best error checking or restrictions on file uploads etc. and things may break as a result of that. We have endeavoured to ensure it conforms to best practices.

## License
Licensed under [MIT](https://opensource.org/licenses/MIT)

The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.
