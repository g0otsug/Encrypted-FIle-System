package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"fixeddemopkl/handlers"
)

var client *mongo.Client
var store = sessions.NewCookieStore([]byte("super-secret-key")) // Secure the session key

func main() {
	var err error
	client, err = mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Define routes, passing the 'store' for session management
	http.HandleFunc("/signup", handlers.SignUpHandler(client))
	http.HandleFunc("/login", handlers.LoginHandler(client, store))                // Passing store here
	http.HandleFunc("/dashboard", handlers.DashboardHandler(client, store))        // Passing store
	http.HandleFunc("/upload", handlers.UploadHandler(client, store))              // Passing store
	http.HandleFunc("/file/view", handlers.ViewFileHandler(client, store))         // Passing store
	http.HandleFunc("/file/download", handlers.DownloadFileHandler(client, store)) // Passing store
	http.HandleFunc("/file/replace", handlers.ReplaceFileHandler(client, store))   // Passing store
	http.HandleFunc("/file/delete", handlers.DeleteFileHandler(client, store))     // Passing store

	// Serve HTML views
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("views"))))

	// Start the server
	log.Println("Server starting at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
