package handlers

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	"fixeddemopkl/models"
)

// GenerateRSAKeys generates a pair of RSA keys (public, private).
func GenerateRSAKeys(bits int) (n, e, d *big.Int, err error) {
	// Generate two random primes p and q
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, nil, err
	}

	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, nil, err
	}

	// Calculate n = p * q
	n = new(big.Int).Mul(p, q)

	// Calculate phi = (p-1) * (q-1)
	pminus1 := new(big.Int).Sub(p, big.NewInt(1))
	qminus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pminus1, qminus1)

	// Public exponent e
	e = big.NewInt(65537) // Commonly used value for e

	// Private exponent d = e^-1 mod(phi)
	d = new(big.Int).ModInverse(e, phi)

	return n, e, d, nil
}

// SignUpHandler handles user signup and generates RSA keys.
func SignUpHandler(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "views/signup.html")
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// Hash the user's password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Unable to create account", http.StatusInternalServerError)
			return
		}

		// Generate RSA keys (512-bit for simplicity; consider using 2048-bit or higher for real applications)
		n, e, d, err := GenerateRSAKeys(512)
		if err != nil {
			http.Error(w, "Unable to generate RSA keys", http.StatusInternalServerError)
			return
		}

		// Create a new user object with RSA keys
		user := models.User{
			Username:    username,
			Password:    string(hashedPassword),
			PublicKeyN:  n.String(), // Store n (modulus) as a string
			PublicKeyE:  e.String(), // Store e (public exponent) as a string
			PrivateKeyD: d.String(), // Store d (private exponent) as a string
		}

		// Insert the user into the MongoDB users collection
		collection := client.Database("go-auth").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			http.Error(w, "Unable to create account", http.StatusInternalServerError)
			return
		}

		// Redirect to login after successful signup
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// LoginHandler handles user login and creates a session.
func LoginHandler(client *mongo.Client, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "views/login.html")
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		collection := client.Database("go-auth").Collection("users")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var user models.User
		err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Create a session and save the user details
		session, _ := store.Get(r, "user-session")
		session.Values["username"] = user.Username
		session.Values["user_id"] = user.ID
		session.Save(r, w)

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

