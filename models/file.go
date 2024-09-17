package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type File struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	FileName       string             `bson:"file_name"`
	FilePath       string             `bson:"file_path"`
	SessionKeyPath string             `bson:"session_key_path"`
	Nonce          string             `bson:"nonce"`
	UploadedBy     string             `bson:"uploaded_by"`
	Timestamp      int64              `bson:"timestamp"`
}
