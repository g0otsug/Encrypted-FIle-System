package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"fixeddemopkl/encryption"
	"fixeddemopkl/models"
)

// DashboardHandler shows the uploaded files in a table.
func DashboardHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the session and check if the user is logged in
		session, _ := store.Get(r, "user-session")
		username, ok := session.Values["username"].(string)
		if !ok || username == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Fetch files from MongoDB
		collection := client.Database("go-auth").Collection("files")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Fetch all files from MongoDB
		cursor, err := collection.Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}))
		if err != nil {
			http.Error(w, "Unable to fetch files", http.StatusInternalServerError)
			return
		}

		var files []models.File
		err = cursor.All(ctx, &files)
		if err != nil {
			http.Error(w, "Unable to parse files", http.StatusInternalServerError)
			return
		}

		// Load and render the dashboard template
		tmpl, err := template.ParseFiles("views/dashboard.html")
		if err != nil {
			http.Error(w, "Unable to load template: "+err.Error(), http.StatusInternalServerError) // Log detailed error
			return
		}

		// Pass the files to the template for rendering
		err = tmpl.Execute(w, struct {
			Files    []models.File
			Username string
		}{
			Files:    files,
			Username: username, // Pass the logged-in user's name
		})
		if err != nil {
			http.Error(w, "Unable to render template: "+err.Error(), http.StatusInternalServerError) // Log detailed error
			return
		}
	}
}

// UploadHandler handles file uploads and encrypts the file and session key.
// UploadHandler handles file uploads and encrypts the file and session key.
func UploadHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Get the session and check if the user is logged in
			session, _ := store.Get(r, "user-session")
			uploaderUsername, ok := session.Values["username"].(string)
			if !ok || uploaderUsername == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Parse the uploaded file
			file, header, err := r.FormFile("file")
			if err != nil {
				http.Error(w, "Unable to upload file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// **Use `header` to get file name**
			fileName := header.Filename // This is where `header` is used

			// Get uploader's user info
			var uploader models.User
			userCollection := client.Database("go-auth").Collection("users")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err = userCollection.FindOne(ctx, bson.M{"username": uploaderUsername}).Decode(&uploader)
			if err != nil {
				http.Error(w, "Unable to find uploader", http.StatusInternalServerError)
				return
			}

			// Step 1: Generate AES session key (256 bits)
			aesKey := encryption.GenerateKey() // 32 bytes = 256-bit AES key
			_, err = rand.Read(aesKey)
			if err != nil {
				http.Error(w, "Unable to generate AES key", http.StatusInternalServerError)
				return
			}

			// Step 2: Encrypt the file using AES-GCM
			plaintext, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, "Unable to read file", http.StatusInternalServerError)
				return
			}
			encryptedFile, nonce, err := encryption.EncryptAESGCM(plaintext, aesKey)
			if err != nil {
				http.Error(w, "Unable to encrypt file", http.StatusInternalServerError)
				return
			}

			// Step 3: Encrypt the session key using the uploader's RSA public key (N, E from the user collection)
			encryptedSessionKey, err := encryption.EncryptRSA(aesKey, uploader.PublicKeyN, uploader.PublicKeyE)
			if err != nil {
				http.Error(w, "Unable to encrypt session key", http.StatusInternalServerError)
				return
			}

			// Step 4: Save the encrypted file and encrypted session key to the shared folder
			encryptedFilePath := filepath.Join("/mnt/c/shared", fileName+".enc") // Save with original file name
			err = os.WriteFile(encryptedFilePath, encryptedFile, 0644)
			if err != nil {
				http.Error(w, "Unable to save encrypted file", http.StatusInternalServerError)
				return
			}

			// Save the encrypted session key (as hex for storage)
			encryptedSessionKeyPath := filepath.Join("/mnt/c/shared", fileName+".key.enc") // Use fileName for session key
			err = os.WriteFile(encryptedSessionKeyPath, []byte(hex.EncodeToString(encryptedSessionKey)), 0644)
			if err != nil {
				http.Error(w, "Unable to save encrypted session key", http.StatusInternalServerError)
				return
			}

			// Store file metadata in MongoDB
			fileCollection := client.Database("go-auth").Collection("files")
			_, err = fileCollection.InsertOne(ctx, bson.M{
				"file_name":        fileName, // Store original file name
				"file_path":        encryptedFilePath,
				"session_key_path": encryptedSessionKeyPath,
				"nonce":            hex.EncodeToString(nonce),
				"uploaded_by":      uploaderUsername,
				"timestamp":        time.Now().Unix(),
			})
			if err != nil {
				http.Error(w, "Unable to save file metadata", http.StatusInternalServerError)
				return
			}

			// Redirect to the dashboard after a successful upload
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		}
	}
}

// ViewFileHandler allows users to view a file in the browser.
func ViewFileHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the file ID from the request query
		fileID := r.URL.Query().Get("id")

		// Convert the fileID from string to ObjectID
		objID, err := primitive.ObjectIDFromHex(fileID)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		// Fetch file details from MongoDB using ObjectID
		collection := client.Database("go-auth").Collection("files")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var file models.File
		err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&file)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Step 1: Retrieve the uploader's private key
		userCollection := client.Database("go-auth").Collection("users")
		var uploader models.User
		err = userCollection.FindOne(ctx, bson.M{"username": file.UploadedBy}).Decode(&uploader)
		if err != nil {
			http.Error(w, "Unable to find uploader", http.StatusInternalServerError)
			return
		}

		// Read the encrypted session key from the file
		encryptedSessionKeyHex, err := os.ReadFile(file.SessionKeyPath)
		if err != nil {
			http.Error(w, "Unable to read encrypted session key", http.StatusInternalServerError)
			return
		}

		encryptedSessionKey, err := hex.DecodeString(string(encryptedSessionKeyHex))
		if err != nil {
			http.Error(w, "Unable to decode encrypted session key", http.StatusInternalServerError)
			return
		}

		// Step 2: Decrypt the session key using the uploader's private RSA key
		sessionKey, err := encryption.DecryptRSA(uploader.PrivateKeyD, uploader.PublicKeyN, encryptedSessionKey)
		if err != nil {
			http.Error(w, "Unable to decrypt session key", http.StatusInternalServerError)
			return
		}

		// Step 3: Retrieve User B’s public key (current user)
		currentUsername := "admin" // Replace with actual session/context user
		var current models.User
		err = userCollection.FindOne(ctx, bson.M{"username": currentUsername}).Decode(&current)
		if err != nil {
			http.Error(w, "Unable to find user", http.StatusInternalServerError)
			return
		}

		// Step 4: Re-encrypt the session key using User B’s public key
		reEncryptedSessionKey, err := encryption.EncryptRSA(sessionKey, current.PublicKeyN, current.PublicKeyE)
		if err != nil {
			http.Error(w, "Unable to re-encrypt session key", http.StatusInternalServerError)
			return
		}

		// Step 5: Decrypt the session key using User B's private RSA key
		decryptedSessionKey, err := encryption.DecryptRSA(current.PrivateKeyD, current.PublicKeyN, reEncryptedSessionKey)
		if err != nil {
			http.Error(w, "Unable to decrypt re-encrypted session key", http.StatusInternalServerError)
			return
		}

		// Step 6: Decrypt the file using the session key
		encryptedFile, err := os.ReadFile(file.FilePath)
		if err != nil {
			http.Error(w, "Unable to read encrypted file", http.StatusInternalServerError)
			return
		}

		nonce, _ := hex.DecodeString(file.Nonce)
		decryptedFile, err := encryption.DecryptAESGCM(encryptedFile, decryptedSessionKey, nonce)
		if err != nil {
			http.Error(w, "Unable to decrypt file", http.StatusInternalServerError)
			return
		}

		// Serve the decrypted file to the user for viewing (not downloading)
		w.Header().Set("Content-Disposition", "inline; filename="+file.FileName)
		w.Header().Set("Content-Type", http.DetectContentType(decryptedFile))
		w.Write(decryptedFile)
	}
}

// DownloadFileHandler allows users to download a decrypted file.
func DownloadFileHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the file ID from the request query
		fileID := r.URL.Query().Get("id")

		// Convert the fileID from string to ObjectID
		objID, err := primitive.ObjectIDFromHex(fileID)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		// Fetch file details from MongoDB using ObjectID
		collection := client.Database("go-auth").Collection("files")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var file models.File
		err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&file)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Decrypt and re-encrypt the session key (same logic as in ViewFileHandler)
		// Step 1: Retrieve the uploader's private key
		userCollection := client.Database("go-auth").Collection("users")
		var uploader models.User
		err = userCollection.FindOne(ctx, bson.M{"username": file.UploadedBy}).Decode(&uploader)
		if err != nil {
			http.Error(w, "Unable to find uploader", http.StatusInternalServerError)
			return
		}

		encryptedSessionKeyHex, err := os.ReadFile(file.SessionKeyPath)
		if err != nil {
			http.Error(w, "Unable to read encrypted session key", http.StatusInternalServerError)
			return
		}

		encryptedSessionKey, err := hex.DecodeString(string(encryptedSessionKeyHex))
		if err != nil {
			http.Error(w, "Unable to decode encrypted session key", http.StatusInternalServerError)
			return
		}

		// Decrypt the session key using the uploader's private RSA key
		sessionKey, err := encryption.DecryptRSA(uploader.PrivateKeyD, uploader.PublicKeyN, encryptedSessionKey)
		if err != nil {
			http.Error(w, "Unable to decrypt session key", http.StatusInternalServerError)
			return
		}

		// Retrieve User B’s public key (current user)
		currentUsername := "admin" // Replace with actual session/context user
		var admin models.User
		err = userCollection.FindOne(ctx, bson.M{"username": currentUsername}).Decode(&admin)
		if err != nil {
			http.Error(w, "Unable to find user", http.StatusInternalServerError)
			return
		}

		// Re-encrypt the session key using User B’s public key
		reEncryptedSessionKey, err := encryption.EncryptRSA(sessionKey, admin.PublicKeyN, admin.PublicKeyE)
		if err != nil {
			http.Error(w, "Unable to re-encrypt session key", http.StatusInternalServerError)
			return
		}

		// Decrypt the session key using User B's private RSA key
		decryptedSessionKey, err := encryption.DecryptRSA(admin.PrivateKeyD, admin.PublicKeyN, reEncryptedSessionKey)
		if err != nil {
			http.Error(w, "Unable to decrypt re-encrypted session key", http.StatusInternalServerError)
			return
		}

		// Decrypt the file using the session key
		encryptedFile, err := os.ReadFile(file.FilePath)
		if err != nil {
			http.Error(w, "Unable to read encrypted file", http.StatusInternalServerError)
			return
		}

		nonce, _ := hex.DecodeString(file.Nonce)
		decryptedFile, err := encryption.DecryptAESGCM(encryptedFile, decryptedSessionKey, nonce)
		if err != nil {
			http.Error(w, "Unable to decrypt file", http.StatusInternalServerError)
			return
		}

		// Set headers to trigger a download
		w.Header().Set("Content-Disposition", "attachment; filename="+file.FileName)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(decryptedFile)
	}
}

// ReplaceFileHandler allows users to replace an existing file.
func ReplaceFileHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get file ID from the query parameter
		fileID := r.URL.Query().Get("id")

		// Convert the fileID from string to ObjectID
		objID, err := primitive.ObjectIDFromHex(fileID)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		// Fetch the current file metadata from MongoDB
		collection := client.Database("go-auth").Collection("files")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var file models.File
		err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&file)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Handle the GET request to show the replace form
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "views/replace.html")
			return
		}

		// Handle the POST request to replace the file
		if r.Method == http.MethodPost {
			// Get the logged-in user (User B)
			session, _ := store.Get(r, "user-session")
			replacerUsername, ok := session.Values["username"].(string)
			if !ok || replacerUsername == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Parse the new file
			newFile, header, err := r.FormFile("file")
			if err != nil {
				http.Error(w, "Unable to upload new file", http.StatusInternalServerError)
				return
			}
			defer newFile.Close()

			// Fetch replacer's user info from MongoDB
			var replacer models.User
			userCollection := client.Database("go-auth").Collection("users")
			err = userCollection.FindOne(ctx, bson.M{"username": replacerUsername}).Decode(&replacer)
			if err != nil {
				http.Error(w, "Unable to find replacer", http.StatusInternalServerError)
				return
			}

			// Step 1: Generate a new AES session key
			aesKey := encryption.GenerateKey() // 256-bit AES key
			_, err = rand.Read(aesKey)
			if err != nil {
				http.Error(w, "Unable to generate AES key", http.StatusInternalServerError)
				return
			}

			// Step 2: Encrypt the new file using AES-GCM
			plaintext, err := io.ReadAll(newFile)
			if err != nil {
				http.Error(w, "Unable to read new file", http.StatusInternalServerError)
				return
			}
			encryptedFile, nonce, err := encryption.EncryptAESGCM(plaintext, aesKey)
			if err != nil {
				http.Error(w, "Unable to encrypt new file", http.StatusInternalServerError)
				return
			}

			// Step 3: Encrypt the session key using replacer's RSA public key
			encryptedSessionKey, err := encryption.EncryptRSA(aesKey, replacer.PublicKeyN, replacer.PublicKeyE)
			if err != nil {
				http.Error(w, "Unable to encrypt session key", http.StatusInternalServerError)
				return
			}

			// Step 4: Save the encrypted file and session key to the Samba folder
			encryptedFilePath := filepath.Join("/mnt/c/shared", header.Filename+".enc")
			err = os.WriteFile(encryptedFilePath, encryptedFile, 0644)
			if err != nil {
				http.Error(w, "Unable to save new encrypted file", http.StatusInternalServerError)
				return
			}

			encryptedSessionKeyPath := filepath.Join("/mnt/c/shared", header.Filename+".key.enc")
			err = os.WriteFile(encryptedSessionKeyPath, []byte(hex.EncodeToString(encryptedSessionKey)), 0644)
			if err != nil {
				http.Error(w, "Unable to save new encrypted session key", http.StatusInternalServerError)
				return
			}

			// Step 5: Delete the old file and session key
			if _, err := os.Stat(file.FilePath); err == nil {
				err = os.Remove(file.FilePath) // Delete the old encrypted file
				if err != nil {
					http.Error(w, "Unable to remove the old file", http.StatusInternalServerError)
					return
				}
			}

			if _, err := os.Stat(file.SessionKeyPath); err == nil {
				err = os.Remove(file.SessionKeyPath) // Delete the old session key
				if err != nil {
					http.Error(w, "Unable to remove the old session key", http.StatusInternalServerError)
					return
				}
			}

			// Step 6: Update MongoDB with new file metadata and uploader
			_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
				"$set": bson.M{
					"file_name":        header.Filename,
					"file_path":        encryptedFilePath,
					"session_key_path": encryptedSessionKeyPath,
					"nonce":            hex.EncodeToString(nonce),
					"uploaded_by":      replacerUsername, // Update the uploaded_by field to User B
					"timestamp":        time.Now().Unix(),
				},
			})
			if err != nil {
				http.Error(w, "Unable to update file metadata", http.StatusInternalServerError)
				return
			}

			// Redirect back to the dashboard after successful replacement
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		}
	}
}

// DeleteFileHandler deletes a file from MongoDB by ID.
// DeleteFileHandler deletes a file from MongoDB and the file system by ID.
func DeleteFileHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileID := r.URL.Query().Get("id")

		// Convert the fileID from string to ObjectID
		objID, err := primitive.ObjectIDFromHex(fileID)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		// Connect to the files collection
		collection := client.Database("go-auth").Collection("files")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Fetch the file details before deletion
		var file models.File
		err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&file)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Delete the document with the specified ObjectID from MongoDB
		deleteResult, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
		if err != nil {
			http.Error(w, "Unable to delete the file metadata", http.StatusInternalServerError)
			return
		}

		// Check if a document was deleted
		if deleteResult.DeletedCount == 0 {
			http.Error(w, "No file found to delete", http.StatusNotFound)
			return
		}

		// Remove the actual file from the Samba share (/mnt/c/shared)
		if _, err := os.Stat(file.FilePath); err == nil {
			err = os.Remove(file.FilePath) // Deletes the file from the disk
			if err != nil {
				http.Error(w, "Unable to remove the file from disk", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "File not found on the server", http.StatusNotFound)
			return
		}

		// Remove the session key file (if any)
		if _, err := os.Stat(file.SessionKeyPath); err == nil {
			err = os.Remove(file.SessionKeyPath) // Deletes the session key file from the disk
			if err != nil {
				http.Error(w, "Unable to remove the session key from disk", http.StatusInternalServerError)
				return
			}
		}

		// Redirect back to the dashboard after deletion
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}
