package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/argon2"
	"log"
	"net/http"
	"time"
)

type UserCreationRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password []byte `json:"password"`
	Salt     []byte `json:"salt"`
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	// Connect to db
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	db := client.Database("go-server")
	users := db.Collection("users")

	// Make email unique
	indexModel := mongo.IndexModel{
		Keys: bson.M{
			"email": 1,
		},
		Options: options.Index().SetUnique(true),
	}
	_, err2 := users.Indexes().CreateOne(context.Background(), indexModel)
	if err2 != nil {
		log.Fatal(err2)
	}

	// Define routes
	r := gin.Default()
	r.GET("/", getHandler)
	r.GET("/users", getAllUsersHandler(users))
	r.POST("/users", createUserHandler(users))
	r.PUT("/users/:id", updateUserHandler(users))
	r.POST("/login", loginHandler(users))
	r.POST("/logout", logoutHandler)
	r.GET("/protected", authMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "You are authorized"})
	})

	fmt.Println("Running server on 8080")
	err3 := r.Run("localhost:8080")
	if err3 != nil {
		fmt.Println("Error running server")
	}
}

func getHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello, world!",
	})
}

func createUserHandler(users *mongo.Collection) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Bind request body to user object
		var userCreationRequest UserCreationRequest
		if err := c.ShouldBindJSON(&userCreationRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		name, email, password := userCreationRequest.Name, userCreationRequest.Email, userCreationRequest.Password
		if name == "" || email == "" || password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Name, Email or Password missing."})
			return
		}
		salt, err := generateSalt()
		hashedPassword, err := hashPassword(password, salt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user := &User{
			Name:     name,
			Email:    email,
			Password: hashedPassword,
			Salt:     salt,
		}

		_, err2 := users.InsertOne(context.Background(), user)
		if mongo.IsDuplicateKeyError(err2) {
			c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
	}
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	// Combine password and salt
	saltedPassword := []byte(password)
	saltedPassword = append(saltedPassword, salt...)

	// Generate hash using Argon2
	hash := argon2.IDKey(saltedPassword, salt, 1, 64*1024, 4, 32)

	return hash, nil
}

func getAllUsersHandler(users *mongo.Collection) func(c *gin.Context) {
	return func(c *gin.Context) {
		filter := bson.M{}
		cursor, err := users.Find(context.Background(), filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var results []User
		if err := cursor.All(context.Background(), &results); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"users": results})
	}
}

func updateUserHandler(users *mongo.Collection) func(c *gin.Context) {
	return func(c *gin.Context) {
		userID := c.Param("id")

		// Create Mongo ObjectId
		objID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Println(userID)
		// Check if user exists
		filter := bson.M{"_id": objID}
		if count, err := users.CountDocuments(context.Background(), filter, nil); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		} else if count == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Bind request body to user object
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Update user in database
		update := bson.M{"$set": user}
		if _, err := users.UpdateOne(context.Background(), filter, update); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
	}
}

func loginHandler(users *mongo.Collection) func(c *gin.Context) {
	return func(c *gin.Context) {
		var creds Credentials
		if err := c.ShouldBindJSON(&creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		email, password := creds.Email, creds.Password
		if email == "" || password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email or Password missing"})
			return
		}

		// Query the database to validate the user credentials
		var user User
		filter := bson.M{"email": email}
		if err := users.FindOne(context.Background(), filter).Decode(&user); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Hash request password with retrieved salt
		hashedPassword, err := hashPassword(password, user.Salt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Check if password valid
		if !bytes.Equal(hashedPassword, user.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}

		// If credentials are valid, create a new JWT token and return it in the response
		token := createToken(creds.Email)
		cookie := http.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: true,
		}

		http.SetCookie(c.Writer, &cookie)

		c.JSON(http.StatusOK, gin.H{"token": token})
	}
}

func logoutHandler(c *gin.Context) {
	cookie := http.Cookie{
		Name:    "jwt",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
		Path:    "/",
	}
	http.SetCookie(c.Writer, &cookie)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func createToken(email string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, _ := token.SignedString([]byte("my_secret_key"))
	return tokenString
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the cookie
		cookie, err := c.Request.Cookie("jwt")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		tokenString := cookie.Value
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("my_secret_key"), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}
		c.Next()
	}
}
