package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
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

	// Connect to Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	// Test Redis connection
	_, errRedis := redisClient.Ping(context.Background()).Result()
	if errRedis != nil {
		panic(err)
	}

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
	r.POST("/login", loginHandler(users, redisClient))
	r.POST("/logout", logoutHandler(redisClient))
	r.GET("/protected", authMiddleware(redisClient), func(c *gin.Context) {
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
		"message": "Go server ready",
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

func loginHandler(users *mongo.Collection, redisClient *redis.Client) func(c *gin.Context) {
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

		// Create a new JWT token
		token := createToken(creds.Email)

		// Generate a new random UUID for sessionID
		sessionID := uuid.New().String()
		// Add session to Redis cache
		err2 := redisClient.Set(c, sessionID, token, time.Hour).Err()
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Set cookie with sessionID
		cookie := http.Cookie{
			Name:     "session",
			Value:    sessionID,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: true,
		}
		http.SetCookie(c.Writer, &cookie)

		c.JSON(http.StatusOK, gin.H{"session": sessionID})
	}
}

func createToken(email string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, _ := token.SignedString([]byte("my_secret_key"))
	return tokenString
}

func logoutHandler(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the session from the cookie
		cookie, err := c.Request.Cookie("session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// Delete session from Redis cache
		err2 := redisClient.Del(c, cookie.Value).Err()
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err2.Error()})
			return
		}

		// Set expire cookie to delete cookie
		expireCookie := http.Cookie{
			Name:    "session",
			Value:   "",
			Expires: time.Now().Add(-time.Hour),
			Path:    "/",
		}
		http.SetCookie(c.Writer, &expireCookie)

		c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
	}
}

func authMiddleware(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the sessionID from the cookie
		cookie, err := c.Request.Cookie("session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		sessionID := cookie.Value

		// Check if session exists in Redis cache and retrieve jwt token
		tokenString, err2 := redisClient.Get(c, sessionID).Result()
		if err2 != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Validate jwt token
		token, err3 := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("my_secret_key"), nil
		})
		if err3 != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}
		c.Next()
	}
}
