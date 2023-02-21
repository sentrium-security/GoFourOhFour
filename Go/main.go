package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
	"time"
)

// Create variables that store the switch values from the user
var (
	username = flag.String("username", "nimda", "The username for authentication.")
	path     = flag.String("path", ".", "Path to the folder to serve. Defaults to current directory")
	port     = flag.Int("port", 8080, "Port to listen on.")
	ssl      = flag.Bool("ssl", false, "Enable SSL. Requires \"go.crt\" and \"go.key\" files")
)

// Create HTML for templates
const homeHtml = `<html>
	<head>
		<title>Home</title>
	</head>
	<body>
	<h2>Simple Go Webserver</h2>
	<a href="/files">Download</a><br>
	<a href="/upload">Upload</a>
	</body>
</html>`

const uploadHtml = `<html>
	<head>
		<title>Upload file</title>
	</head>
	<body>
	<h2>Upload File</h2>
	<form enctype="multipart/form-data" action="{{.Proto}}://{{.IpAddr}}:{{.Port}}/upload" method="post">
		<input type="file" name="file" />
		<input type="submit" value="upload" />
	</form>
	<br>
	<a href="/">Home</a>
	</body>
</html>`

const successHtml = `<html>
	<head>
		<title>Success</title>
	</head>
	<body>
	<h2>File uploaded and saved successfully</h2><br>
	<a href="/files">Download</a><br>
	<a href="/upload">Upload</a>
	</body>
</html>`

const listFilesHtml = `<html>
	<head>
		<title>File List</title>
	</head>
	<body>
	<h2>Download File</h2>
	%s
	<br>
	<a href="/">Home</a>
	</body>
</html>`

// Generate and store the password for authentication.
var (
	creds       = generatePassword()
	password    = creds[0]
	encoded     = creds[1]
	lastRequest time.Time
)

func main() {
	// Parse the flog options, get IP address and set the last request to now
	flag.Parse()
	ipadd := getIP()
	lastRequest = time.Now()

	// HTTP handlers that can be handled outside of https/http servers
	http.HandleFunc("/", auth(index()))
	http.HandleFunc("/files", auth(handleListFiles()))
	http.HandleFunc("/download/", auth(handleDownload()))

	// If user wants SSL, create TLS config etc.
	if *ssl {
		banner(443, ipadd, "https", true)
		http.HandleFunc("/upload", auth(upload(ipadd, "https", 443)))

		// Certficate files
		const (
			localCertFile = "go.crt"
			localKeyFile  = "go.key"
		)

		// Load the SSL certificate and key
		cert, err := tls.LoadX509KeyPair(localCertFile, localKeyFile)
		if err != nil {
			fmt.Println("Error loading SSL certificate:", err)
			os.Exit(1)
		}

		// Create a TLS config with the certificate and key
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Create a server with the TLS config
		srv := &http.Server{
			Addr:      fmt.Sprintf(":%d", 443),
			TLSConfig: tlsConfig,
			Handler:   logger(http.DefaultServeMux),
		}

		fmt.Printf("Starting server on port %d\n", 443)
		go func() {
			err = srv.ListenAndServeTLS("", "")
			if err != nil && err != http.ErrServerClosed {
				fmt.Println("Error starting server:", err)
				os.Exit(1)
			}
		}()

		// Checks when last request was made to server and will close after inactivity
		fmt.Printf("Starting Ticker...%s\n", lastRequest.Format(time.UnixDate))
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			if time.Since(lastRequest) >= time.Minute*2 {
				fmt.Println("Closing server due to inactivity")
				srv.Close()
				os.Exit(0)
			}
		}
		// Create HTTP server
	} else {
		banner(*port, ipadd, "http", false)
		http.HandleFunc("/upload", auth(upload(ipadd, "http", *port)))

		// Server options
		srv := &http.Server{
			Addr:    fmt.Sprintf(":%d", *port),
			Handler: logger(http.DefaultServeMux),
		}

		fmt.Printf("Starting server on port %d\n\n", *port)
		go func() {
			err := srv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				fmt.Println("Error starting server:", err)
				os.Exit(1)
			}
		}()

		// Checks when last request was made to server and will close after inactivity
		fmt.Printf("Starting Ticker...%s\n", lastRequest.Format(time.UnixDate))
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			if time.Since(lastRequest) >= time.Minute*2 {
				fmt.Println("Closing server due to inactivity")
				srv.Close()
				os.Exit(0)
			}
		}

	}
}

// Home
func index() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			t := template.Must(template.New("Home").Parse(homeHtml))
			t.Execute(w, homeHtml)
			return
		}
	})
}

// Return a list of files from the path flag
func handleListFiles() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files, err := getFilesInDir(*path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate HTML for file list
		var html string
		for _, f := range files {
			link := fmt.Sprintf("<a href=\"/download/%s\">%s</a>", f, f)
			html += fmt.Sprintf("%s<br>", link)
		}

		// Write HTML response to client
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, listFilesHtml, html)

	})
}

// Get the list of files from path
func getFilesInDir(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, info.Name())
		}
		return nil
	})
	return files, err
}

// Return files for download
func handleDownload() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := filepath.Join(*path, filepath.Base(r.URL.Path))
		filename := filepath.Base(r.URL.Path)
		contentDisposition := fmt.Sprintf("attachment; filename=\"%s\"", filename)
		w.Header().Set("Content-Disposition", contentDisposition)

		http.ServeFile(w, r, file)
	})
}

// Handle file uploads
func upload(ip net.IP, proto string, port int) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// new to this but this is the way I've used to get two variables passed to the HTML
		type Variables struct {
			IpAddr net.IP
			Port   string
			Proto  string
		}

		v := Variables{
			IpAddr: ip,
			Port:   strconv.Itoa(port),
			Proto:  proto,
		}

		if r.Method == http.MethodGet {
			t := template.Must(template.New("Upload").Parse(uploadHtml))
			t.Execute(w, &v)
			return
		}
		// Parse the file from the request
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Error parsing file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Location to save the file
		filename := filepath.Join(*path, header.Filename)

		// Save the file to disk
		out, err := os.Create(filename)
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}
		t := template.Must(template.New("Home").Parse(successHtml))
		t.Execute(w, successHtml)
		// fmt.Fprintf(w, "File uploaded and saved successfully")
	})

}

// Auth middleware
func auth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != *username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// Get preferred outbound ip of this machine
func getIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// Log handler for HTTP requests
func logger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// update the last request each time a request is made
		lastRequest = time.Now()
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}

// Generate a random password for authentication
func generatePassword() [2]string {
	randomBytes := make([]byte, 20)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(err)
	}
	randomString := base64.RawURLEncoding.EncodeToString(randomBytes)[:14]
	// create the format username:password for base64 encode
	usernamePasswordString := *username + ":" + randomString
	encoded := base64.StdEncoding.EncodeToString([]byte(usernamePasswordString))
	creds := [2]string{randomString, encoded}
	return creds
}

// Print banner based on which server is started
func banner(port int, ipadd net.IP, proto string, ssl bool) {
	fmt.Printf("### WARNING FILES WILL BE EXPOSED / UPLOADED TO DIRECTORY: %s ###\n", *path)
	fmt.Println("---------------------------------------------------------------------")
	fmt.Printf("The password for web login is %s\n", password)

	if ssl {
		fmt.Printf("curl -k -H \"Authorization: Basic %s\" -F file=@filename.txt %s://%s/upload\n", encoded, proto, ipadd)
		fmt.Printf("curl -k -H \"Authorization: Basic %s\" %s://%s/download/filename.txt\n", encoded, proto, ipadd)
	} else {
		fmt.Printf("curl -H \"Authorization: Basic %s\" -F file=@filename.txt %s://%s:%d/upload\n", encoded, proto, ipadd, port)
		fmt.Printf("curl -H \"Authorization: Basic %s\" %s://%s:%d/download/filename.txt\n", encoded, proto, ipadd, port)
		fmt.Println("Enable SSL with -ssl=true (requires a \"go.crt\" and \"go.key\" file)")
	}

	fmt.Println("---------------------------------------------------------------------")
}
