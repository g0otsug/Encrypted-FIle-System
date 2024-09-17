package models

// User represents a registered user with RSA keys.
type User struct {
	ID          string `bson:"_id,omitempty"`
	Username    string `bson:"username"`
	Password    string `bson:"password"`
	PublicKeyN  string `bson:"public_key_n"`  // RSA public key (modulus)
	PublicKeyE  string `bson:"public_key_e"`  // RSA public key (exponent)
	PrivateKeyD string `bson:"private_key_d"` // RSA private key (exponent)
}
