package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "strings"
    "strconv"
    "time"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    "bytes"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    "github.com/rs/cors"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "golang.org/x/crypto/bcrypt"
	"crypto/tls"
)

type User struct {
    Username string `json:"username" bson:"username"`
    Password string `json:"password,omitempty" bson:"-"`
    Hash     string `json:"-" bson:"password"`
    Email    string `json:"email" bson:"email"`
    OTP      string `json:"-" bson:"otp,omitempty"`
    OTPExpiry time.Time `json:"-" bson:"otpExpiry,omitempty"`
    ResetToken   string `json:"-" bson:"resetToken,omitempty"`
    ResetExpiry  time.Time `json:"-" bson:"resetExpiry,omitempty"`
    GoogleID     string `json:"-" bson:"googleId,omitempty"`
}

type Story struct {
    ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
    Title       string            `json:"title" bson:"title"`
    Description string            `json:"description" bson:"description"`
    AuthorID    string            `json:"authorId" bson:"authorId"`
    IsPublic    bool              `json:"isPublic" bson:"isPublic"`
    CreatedAt   time.Time         `json:"createdAt" bson:"createdAt"`
    UpdatedAt   time.Time         `json:"updatedAt" bson:"updatedAt"`
}

type Chapter struct {
    ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
    StoryID   primitive.ObjectID `json:"storyId" bson:"storyId"`
    Title     string            `json:"title" bson:"title"`
    Content   string            `json:"content" bson:"content"`
    Order     int               `json:"order" bson:"order"`
    IsPublic  bool              `json:"isPublic" bson:"isPublic"`
    CreatedAt time.Time         `json:"createdAt" bson:"createdAt"`
    UpdatedAt time.Time         `json:"updatedAt" bson:"updatedAt"`
}

type StoryMetadata struct {
    Story    Story `json:"story"`
    Chapters int   `json:"chapterCount"`
}

type Response struct {
    Status  string      `json:"status"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}

type LoginResponse struct {
    Token string `json:"token"`
}

var client *mongo.Client
var users *mongo.Collection
var stories *mongo.Collection
var chapters *mongo.Collection
var jwtKey = []byte("your-secret-key") // In production, use environment variable
var brevoAPIKey = os.Getenv("BREVO_API_KEY")
var emailFrom = os.Getenv("EMAIL_FROM") 
var emailFromName = os.Getenv("EMAIL_FROM_NAME")
var frontendURL   = os.Getenv("FRONTEND_URL")
var googleOauthConfig = &oauth2.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
    Scopes: []string{
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    },
    Endpoint: google.Endpoint,
}

func main() {
    // Load .env file before using any env variables
    err := godotenv.Load()
    if err != nil {
        log.Printf("Error loading .env file: %v", err)
        // Continue execution, don't fatal as the env vars might be set directly
    }

    // Move these variables inside main() after loading .env
    brevoAPIKey = os.Getenv("BREVO_API_KEY")
    emailFrom = os.Getenv("EMAIL_FROM") 
    emailFromName = os.Getenv("EMAIL_FROM_NAME")
    frontendURL = os.Getenv("FRONTEND_URL")
    googleOauthConfig = &oauth2.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
        Scopes: []string{
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        },
        Endpoint: google.Endpoint,
    }

    // Connect to MongoDB with longer timeout and TLS config
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    mongoURI := os.Getenv("db_uri")
    log.Printf("Attempting to connect with URI: %s", strings.Replace(mongoURI, "://" + strings.Split(strings.Split(mongoURI, "://")[1], "@")[0], "://[REDACTED]", 1))

    // Configure MongoDB client options
    clientOptions := options.Client().ApplyURI(mongoURI)
    clientOptions.SetTLSConfig(&tls.Config{
        MinVersion: tls.VersionTLS12,
    })
    clientOptions.SetServerAPIOptions(options.ServerAPI(options.ServerAPIVersion1))

    // Connect with configured options
    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        log.Printf("Connection error: %v", err)
        log.Fatal(err)
    }
    log.Printf("Connected to MongoDB")

    // Verify connection with ping
    log.Printf("Pinging MongoDB")
    if err := client.Ping(ctx, nil); err != nil {
        log.Printf("Ping error: %v", err)
        // Don't fatal here since we want to see the full error in logs
        log.Printf("%v", err) 
        os.Exit(1)
    }
    log.Printf("Successfully pinged MongoDB")

    defer client.Disconnect(ctx)

    log.Printf("Getting database writer_db")
    db := client.Database("writer_db")
    log.Printf("Database: writer_db")
    users = db.Collection("users")
    log.Printf("Collection: users")
    stories = db.Collection("stories")
    log.Printf("Collection: stories")
    chapters = db.Collection("chapters")
    log.Printf("Collection: chapters")

    // Create indexes
    log.Printf("Creating indexes")
    indexModels := []mongo.IndexModel{
        {
            Keys:    bson.D{{Key: "username", Value: 1}},
            Options: options.Index().SetUnique(true),
        },
        {
            Keys: bson.D{{Key: "authorId", Value: 1}},
        },
        {
            Keys: bson.D{
                {Key: "storyId", Value: 1},
                {Key: "order", Value: 1},
            },
        },
    }
    log.Printf("Created index models for username, authorId, and storyId+order")

    _, err = users.Indexes().CreateMany(ctx, indexModels[:1])
    if err != nil {
        log.Fatal(err)
    }
    _, err = stories.Indexes().CreateMany(ctx, indexModels[1:2])
    if err != nil {
        log.Fatal(err)
    }
    _, err = chapters.Indexes().CreateMany(ctx, indexModels[2:])
    if err != nil {
        log.Fatal(err)
    }

    // Router setup
    r := mux.NewRouter()
    log.Printf("Router setup")    

    // CORS middleware
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"}, // Allow all origins
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"*"}, // Allow all headers
        ExposedHeaders: []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge: 300, // Maximum value not ignored by any of major browsers
    })
    log.Printf("CORS middleware setup")

    // Middleware for logging
    r.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            log.Printf("%s %s", r.Method, r.RequestURI)
            next.ServeHTTP(w, r)
        })
    })

    // Public routes
    r.HandleFunc("/health", healthHandler).Methods("GET")
    r.HandleFunc("/signup", signupHandler).Methods("POST")
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/stories", getAllStoriesHandler).Methods("GET")
    r.HandleFunc("/stories/{id}/chapters", getAllChaptersHandler).Methods("GET")
    r.HandleFunc("/users/{username}/stories", getUserPublicStoriesHandler).Methods("GET")
    r.HandleFunc("/users/{username}/stories/{id}/chapters", getUserPublicChaptersHandler).Methods("GET")
    r.HandleFunc("/forgot-password", forgotPasswordHandler).Methods("POST")
    r.HandleFunc("/reset-password", resetPasswordHandler).Methods("POST")
    r.HandleFunc("/login/email", emailLoginHandler).Methods("POST")
    r.HandleFunc("/verify-otp", verifyOTPHandler).Methods("POST")
    r.HandleFunc("/auth/google", googleAuthHandler).Methods("GET")
    r.HandleFunc("/auth/google/callback", googleCallbackHandler).Methods("GET")

    // Protected routes
    protected := r.PathPrefix("/api").Subrouter()
    protected.Use(authMiddleware)
    protected.HandleFunc("/profile", profileHandler).Methods("GET")
    
    // Story routes
    protected.HandleFunc("/stories", createStoryHandler).Methods("POST")
    protected.HandleFunc("/stories", getUserStoriesHandler).Methods("GET")
    protected.HandleFunc("/stories/{id}", getStoryHandler).Methods("GET")
    protected.HandleFunc("/stories/{id}", updateStoryHandler).Methods("PUT")
    protected.HandleFunc("/stories/{id}", deleteStoryHandler).Methods("DELETE")
    protected.HandleFunc("/stories/{id}/visibility", updateStoryVisibilityHandler).Methods("PUT")
    
    // Chapter routes
    protected.HandleFunc("/stories/{id}/chapters", createChapterHandler).Methods("POST")
    protected.HandleFunc("/stories/{id}/chapters", getStoryChaptersHandler).Methods("GET")
    protected.HandleFunc("/chapters/{id}", getChapterHandler).Methods("GET")
    protected.HandleFunc("/chapters/{id}", updateChapterHandler).Methods("PUT")
    protected.HandleFunc("/chapters/{id}", deleteChapterHandler).Methods("DELETE")
    protected.HandleFunc("/chapters/{id}/visibility", updateChapterVisibilityHandler).Methods("PUT")

    // Start server with CORS
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server starting on :%s", port)
    log.Fatal(http.ListenAndServe(":"+port, c.Handler(r)))
}

// New handlers for public user stories/chapters
func getUserPublicStoriesHandler(w http.ResponseWriter, r *http.Request) {
    username := mux.Vars(r)["username"]
    
    pipeline := mongo.Pipeline{
        bson.D{{Key: "$match", Value: bson.D{
            {Key: "authorId", Value: username},
            {Key: "isPublic", Value: true},
        }}},
        bson.D{{Key: "$lookup", Value: bson.D{
            {Key: "from", Value: "chapters"},
            {Key: "localField", Value: "_id"},
            {Key: "foreignField", Value: "storyId"},
            {Key: "as", Value: "chapters"},
        }}},
        bson.D{{Key: "$project", Value: bson.D{
            {Key: "story", Value: "$$ROOT"},
            {Key: "chapterCount", Value: bson.D{{Key: "$size", Value: "$chapters"}}},
        }}},
    }

    cursor, err := stories.Aggregate(context.Background(), pipeline)
    if err != nil {
        sendError(w, "Error fetching stories", http.StatusInternalServerError)
        return
    }

    var results []StoryMetadata
    if err = cursor.All(context.Background(), &results); err != nil {
        sendError(w, "Error processing stories", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: results})
}

func getUserPublicChaptersHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    username := vars["username"]
    storyID, err := primitive.ObjectIDFromHex(vars["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    // Verify story is public
    var story Story
    err = stories.FindOne(context.Background(), bson.M{
        "_id": storyID,
        "authorId": username,
        "isPublic": true,
    }).Decode(&story)
    if err != nil {
        sendError(w, "Story not found", http.StatusNotFound)
        return
    }

    cursor, err := chapters.Find(context.Background(), 
        bson.M{
            "storyId": storyID,
            "isPublic": true,
        },
        options.Find().SetSort(bson.D{{Key: "order", Value: 1}}))
    if err != nil {
        sendError(w, "Error fetching chapters", http.StatusInternalServerError)
        return
    }

    var chapters []Chapter
    if err = cursor.All(context.Background(), &chapters); err != nil {
        sendError(w, "Error processing chapters", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: chapters})
}

// New handlers for updating visibility
func updateStoryVisibilityHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    var visibility struct {
        IsPublic bool `json:"isPublic"`
    }
    if err := json.NewDecoder(r.Body).Decode(&visibility); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    result := stories.FindOneAndUpdate(
        context.Background(),
        bson.M{"_id": id, "authorId": r.Header.Get("username")},
        bson.M{"$set": bson.M{"isPublic": visibility.IsPublic}},
        options.FindOneAndUpdate().SetReturnDocument(options.After),
    )

    var story Story
    if err := result.Decode(&story); err != nil {
        sendError(w, "Story not found or unauthorized", http.StatusNotFound)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Story visibility updated", Data: story})
}

func updateChapterVisibilityHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid chapter ID", http.StatusBadRequest)
        return
    }

    var visibility struct {
        IsPublic bool `json:"isPublic"`
    }
    if err := json.NewDecoder(r.Body).Decode(&visibility); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Verify ownership through aggregation
    pipeline := []bson.M{
        {"$match": bson.M{"_id": id}},
        {"$lookup": bson.M{
            "from":         "stories",
            "localField":   "storyId",
            "foreignField": "_id",
            "as":          "story",
        }},
        {"$unwind": "$story"},
        {"$match": bson.M{"story.authorId": r.Header.Get("username")}},
    }

    cursor, err := chapters.Aggregate(context.Background(), pipeline)
    if err != nil || !cursor.Next(context.Background()) {
        sendError(w, "Chapter not found or unauthorized", http.StatusNotFound)
        return
    }

    result := chapters.FindOneAndUpdate(
        context.Background(),
        bson.M{"_id": id},
        bson.M{"$set": bson.M{"isPublic": visibility.IsPublic}},
        options.FindOneAndUpdate().SetReturnDocument(options.After),
    )

    var chapter Chapter
    if err := result.Decode(&chapter); err != nil {
        sendError(w, "Error updating chapter visibility", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Chapter visibility updated", Data: chapter})
}

func generateToken(username string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256,
        jwt.MapClaims{
            "username": username,
            "exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 hour expiry
        })
    return token.SignedString(jwtKey)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            sendError(w, "No authorization header", http.StatusUnauthorized)
            return
        }

        tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })

        if err != nil || !token.Valid {
            sendError(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            sendError(w, "Invalid token claims", http.StatusUnauthorized)
            return
        }

        r.Header.Set("username", claims["username"].(string))
        next.ServeHTTP(w, r)
    })
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    sendJSON(w, Response{Status: "success", Message: "Server is healthy"})
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate input
    if user.Username == "" || user.Password == "" {
        sendError(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    // Hash password
    hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        sendError(w, "Error processing password", http.StatusInternalServerError)
        return
    }

    // Save user
    user.Hash = string(hash)
    _, err = users.InsertOne(context.Background(), user)
    if err != nil {
        sendError(w, "Username already exists", http.StatusBadRequest)
        return
    }

    // Generate token
    token, err := generateToken(user.Username)
    if err != nil {
        sendError(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{
        Status:  "success",
        Message: "User created successfully",
        Data:    LoginResponse{Token: token},
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var loginUser User
    if err := json.NewDecoder(r.Body).Decode(&loginUser); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Find user
    var user User
    err := users.FindOne(context.Background(), bson.M{"username": loginUser.Username}).Decode(&user)
    if err != nil {
        sendError(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Check password
    err = bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(loginUser.Password))
    if err != nil {
        sendError(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate token
    token, err := generateToken(user.Username)
    if err != nil {
        sendError(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{
        Status:  "success",
        Message: "Login successful",
        Data:    LoginResponse{Token: token},
    })
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    username := r.Header.Get("username")
    sendJSON(w, Response{
        Status:  "success",
        Message: "Profile accessed",
        Data:    map[string]string{"username": username},
    })
}

func createStoryHandler(w http.ResponseWriter, r *http.Request) {
    var story Story
    if err := json.NewDecoder(r.Body).Decode(&story); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    story.AuthorID = r.Header.Get("username")
    story.CreatedAt = time.Now()
    story.UpdatedAt = time.Now()

    result, err := stories.InsertOne(context.Background(), story)
    if err != nil {
        sendError(w, "Error creating story", http.StatusInternalServerError)
        return
    }

    story.ID = result.InsertedID.(primitive.ObjectID)
    sendJSON(w, Response{Status: "success", Message: "Story created", Data: story})
}

func getUserStoriesHandler(w http.ResponseWriter, r *http.Request) {
    username := r.Header.Get("username")
    
    // Use aggregation to get stories with chapter counts
    pipeline := mongo.Pipeline{
        bson.D{{Key: "$match", Value: bson.D{{Key: "authorId", Value: username}}}},
        bson.D{{Key: "$lookup", Value: bson.D{
            {Key: "from", Value: "chapters"},
            {Key: "localField", Value: "_id"},
            {Key: "foreignField", Value: "storyId"},
            {Key: "as", Value: "chapters"},
        }}},
        bson.D{{Key: "$project", Value: bson.D{
            {Key: "story", Value: "$$ROOT"},
            {Key: "chapterCount", Value: bson.D{{Key: "$size", Value: "$chapters"}}},
        }}},
    }

    cursor, err := stories.Aggregate(context.Background(), pipeline)
    if err != nil {
        sendError(w, "Error fetching stories", http.StatusInternalServerError)
        return
    }

    var results []StoryMetadata
    if err = cursor.All(context.Background(), &results); err != nil {
        sendError(w, "Error processing stories", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: results})
}

func getAllStoriesHandler(w http.ResponseWriter, r *http.Request) {
    // Use aggregation to get all public stories with chapter counts
    pipeline := mongo.Pipeline{
        bson.D{{Key: "$match", Value: bson.D{{Key: "isPublic", Value: true}}}},
        bson.D{{Key: "$lookup", Value: bson.D{
            {Key: "from", Value: "chapters"},
            {Key: "localField", Value: "_id"},
            {Key: "foreignField", Value: "storyId"},
            {Key: "as", Value: "chapters"},
        }}},
        bson.D{{Key: "$project", Value: bson.D{
            {Key: "story", Value: "$$ROOT"},
            {Key: "chapterCount", Value: bson.D{{Key: "$size", Value: "$chapters"}}},
        }}},
    }

    cursor, err := stories.Aggregate(context.Background(), pipeline)
    if err != nil {
        sendError(w, "Error fetching stories", http.StatusInternalServerError)
        return
    }

    var results []StoryMetadata
    if err = cursor.All(context.Background(), &results); err != nil {
        sendError(w, "Error processing stories", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: results})
}

func getAllChaptersHandler(w http.ResponseWriter, r *http.Request) {
    storyID, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    // Verify story is public
    var story Story
    err = stories.FindOne(context.Background(), bson.M{
        "_id": storyID,
        "isPublic": true,
    }).Decode(&story)
    if err != nil {
        sendError(w, "Story not found", http.StatusNotFound)
        return
    }

    // Get public chapters with pagination
    opts := options.Find().
        SetSort(bson.D{primitive.E{Key: "order", Value: 1}})

    cursor, err := chapters.Find(context.Background(), 
        bson.M{
            "storyId": storyID,
            "isPublic": true,
        }, opts)
    if err != nil {
        sendError(w, "Error fetching chapters", http.StatusInternalServerError)
        return
    }

    var chapters []Chapter
    if err = cursor.All(context.Background(), &chapters); err != nil {
        sendError(w, "Error processing chapters", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: chapters})
}

func getStoryHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    var story Story
    err = stories.FindOne(context.Background(), bson.M{"_id": id}).Decode(&story)
    if err != nil {
        sendError(w, "Story not found", http.StatusNotFound)
        return
    }

    if story.AuthorID != r.Header.Get("username") {
        sendError(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    sendJSON(w, Response{Status: "success", Data: story})
}

func updateStoryHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    var story Story
    if err := json.NewDecoder(r.Body).Decode(&story); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    story.UpdatedAt = time.Now()
    update := bson.M{
        "$set": bson.M{
            "title":       story.Title,
            "description": story.Description,
            "isPublic":    story.IsPublic,
            "updatedAt":   story.UpdatedAt,
        },
    }

    result := stories.FindOneAndUpdate(
        context.Background(),
        bson.M{"_id": id, "authorId": r.Header.Get("username")},
        update,
        options.FindOneAndUpdate().SetReturnDocument(options.After),
    )

    if result.Err() != nil {
        sendError(w, "Story not found or unauthorized", http.StatusNotFound)
        return
    }

    if err := result.Decode(&story); err != nil {
        sendError(w, "Error updating story", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Story updated", Data: story})
}

func deleteStoryHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    // Start a session for transaction
    session, err := client.StartSession()
    if err != nil {
        sendError(w, "Error starting session", http.StatusInternalServerError)
        return
    }
    defer session.EndSession(context.Background())

    // Delete story and its chapters in a transaction
    err = session.StartTransaction()
    if err != nil {
        sendError(w, "Error starting transaction", http.StatusInternalServerError)
        return
    }

    if err = mongo.WithSession(context.Background(), session, func(sc mongo.SessionContext) error {
        // Delete story
        result, err := stories.DeleteOne(sc, bson.M{
            "_id":     id,
            "authorId": r.Header.Get("username"),
        })
        if err != nil {
            return err
        }
        if result.DeletedCount == 0 {
            return mongo.ErrNoDocuments
        }

        // Delete all chapters
        _, err = chapters.DeleteMany(sc, bson.M{"storyId": id})
        return err
    }); err != nil {
        session.AbortTransaction(context.Background())
        if err == mongo.ErrNoDocuments {
            sendError(w, "Story not found or unauthorized", http.StatusNotFound)
        } else {
            sendError(w, "Error deleting story", http.StatusInternalServerError)
        }
        return
    }

    if err = session.CommitTransaction(context.Background()); err != nil {
        sendError(w, "Error committing transaction", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Story deleted"})
}

func createChapterHandler(w http.ResponseWriter, r *http.Request) {
    storyID, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    var chapter Chapter
    if err := json.NewDecoder(r.Body).Decode(&chapter); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Verify story ownership
    var story Story
    err = stories.FindOne(context.Background(), bson.M{
        "_id":     storyID,
        "authorId": r.Header.Get("username"),
    }).Decode(&story)
    if err != nil {
        sendError(w, "Story not found or unauthorized", http.StatusNotFound)
        return
    }

    chapter.StoryID = storyID
    chapter.CreatedAt = time.Now()
    chapter.UpdatedAt = time.Now()

    result, err := chapters.InsertOne(context.Background(), chapter)
    if err != nil {
        sendError(w, "Error creating chapter", http.StatusInternalServerError)
        return
    }

    chapter.ID = result.InsertedID.(primitive.ObjectID)
    sendJSON(w, Response{Status: "success", Message: "Chapter created", Data: chapter})
}

func getStoryChaptersHandler(w http.ResponseWriter, r *http.Request) {
    storyID, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid story ID", http.StatusBadRequest)
        return
    }

    // Verify story ownership
    var story Story
    err = stories.FindOne(context.Background(), bson.M{
        "_id":     storyID,
        "authorId": r.Header.Get("username"),
    }).Decode(&story)
    if err != nil {
        sendError(w, "Story not found or unauthorized", http.StatusNotFound)
        return
    }

    // Pagination parameters
    page := 1
    limit := 10
    if p := r.URL.Query().Get("page"); p != "" {
        if val, err := strconv.Atoi(p); err == nil && val > 0 {
            page = val
        }
    }
    skip := (page - 1) * limit

    // Get chapters with pagination
    opts := options.Find().
        SetSort(bson.D{primitive.E{Key: "order", Value: 1}}).
        SetSkip(int64(skip)).
        SetLimit(int64(limit))

    cursor, err := chapters.Find(context.Background(), 
        bson.M{"storyId": storyID}, opts)
    if err != nil {
        sendError(w, "Error fetching chapters", http.StatusInternalServerError)
        return
    }

    var chapters []Chapter
    if err = cursor.All(context.Background(), &chapters); err != nil {
        sendError(w, "Error processing chapters", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: chapters})
}

func getChapterHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid chapter ID", http.StatusBadRequest)
        return
    }

    var chapter Chapter
    pipeline := []bson.M{
        {"$match": bson.M{"_id": id}},
        {"$lookup": bson.M{
            "from":         "stories",
            "localField":   "storyId",
            "foreignField": "_id",
            "as":          "story",
        }},
        {"$unwind": "$story"},
        {"$match": bson.M{"story.authorId": r.Header.Get("username")}},
    }

    cursor, err := chapters.Aggregate(context.Background(), pipeline)
    if err != nil {
        sendError(w, "Error fetching chapter", http.StatusInternalServerError)
        return
    }

    if !cursor.Next(context.Background()) {
        sendError(w, "Chapter not found or unauthorized", http.StatusNotFound)
        return
    }

    if err := cursor.Decode(&chapter); err != nil {
        sendError(w, "Error processing chapter", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Data: chapter})
}

func updateChapterHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid chapter ID", http.StatusBadRequest)
        return
    }

    var chapter Chapter
    if err := json.NewDecoder(r.Body).Decode(&chapter); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Verify ownership through aggregation
    pipeline := []bson.M{
        {"$match": bson.M{"_id": id}},
        {"$lookup": bson.M{
            "from":         "stories",
            "localField":   "storyId",
            "foreignField": "_id",
            "as":          "story",
        }},
        {"$unwind": "$story"},
        {"$match": bson.M{"story.authorId": r.Header.Get("username")}},
    }

    cursor, err := chapters.Aggregate(context.Background(), pipeline)
    if err != nil || !cursor.Next(context.Background()) {
        sendError(w, "Chapter not found or unauthorized", http.StatusNotFound)
        return
    }

    chapter.UpdatedAt = time.Now()
    update := bson.M{
        "$set": bson.M{
            "title":     chapter.Title,
            "content":   chapter.Content,
            "order":     chapter.Order,
            "updatedAt": chapter.UpdatedAt,
        },
    }

    result := chapters.FindOneAndUpdate(
        context.Background(),
        bson.M{"_id": id},
        update,
        options.FindOneAndUpdate().SetReturnDocument(options.After),
    )

    if err := result.Decode(&chapter); err != nil {
        sendError(w, "Error updating chapter", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Chapter updated", Data: chapter})
}

func deleteChapterHandler(w http.ResponseWriter, r *http.Request) {
    id, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
    if err != nil {
        sendError(w, "Invalid chapter ID", http.StatusBadRequest)
        return
    }

    // Verify ownership through aggregation
    pipeline := []bson.M{
        {"$match": bson.M{"_id": id}},
        {"$lookup": bson.M{
            "from":         "stories",
            "localField":   "storyId",
            "foreignField": "_id",
            "as":          "story",
        }},
        {"$unwind": "$story"},
        {"$match": bson.M{"story.authorId": r.Header.Get("username")}},
    }

    cursor, err := chapters.Aggregate(context.Background(), pipeline)
    if err != nil || !cursor.Next(context.Background()) {
        sendError(w, "Chapter not found or unauthorized", http.StatusNotFound)
        return
    }

    _, err = chapters.DeleteOne(context.Background(), bson.M{"_id": id})
    if err != nil {
        sendError(w, "Error deleting chapter", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Chapter deleted"})
}

func sendJSON(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, message string, code int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(Response{Status: "error", Message: message})
}

func generateOTP() string {
    b := make([]byte, 3) // 6 digits = 3 bytes
    rand.Read(b)
    return fmt.Sprintf("%06d", base64.StdEncoding.EncodeToString(b))[:6]
}

func generateRandomToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func sendEmail(to, subject, body string) error {
    payload := map[string]interface{}{
        "sender": map[string]string{
            "name":  emailFromName,
            "email": emailFrom,
        },
        "to": []map[string]string{
            {"email": to},
        },
        "subject": subject,
        "htmlContent": body,
    }

    jsonData, err := json.Marshal(payload)
    if err != nil {
        return err
    }

    req, err := http.NewRequest("POST", "https://api.brevo.com/v3/smtp/email", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    req.Header.Set("accept", "application/json")
    req.Header.Set("api-key", brevoAPIKey)
    req.Header.Set("content-type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        var errorResponse struct {
            Message string `json:"message"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
            return fmt.Errorf("email service error: %d", resp.StatusCode)
        }
        return fmt.Errorf("email service error: %s", errorResponse.Message)
    }

    return nil
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("Received forgot password request")
    
    var req struct {
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Error decoding request body: %v", err)
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    log.Printf("Generating reset token for email: %s", req.Email)
    resetToken := generateRandomToken()
    expiry := time.Now().Add(15 * time.Minute)

    log.Printf("Updating user record with reset token")
    result := users.FindOneAndUpdate(
        context.Background(),
        bson.M{"email": req.Email},
        bson.M{"$set": bson.M{
            "resetToken":  resetToken,
            "resetExpiry": expiry,
        }},
    )
    if result.Err() != nil {
        log.Printf("Email not found: %s", req.Email)
        sendError(w, "Email not found", http.StatusNotFound)
        return
    }

    log.Printf("Generating reset password email")
    resetLink := fmt.Sprintf("%s/reset-password?token=%s", frontendURL, resetToken)
    emailBody := fmt.Sprintf(`
        <h1>Password Reset Request</h1>
        <p>Click the following link to reset your password:</p>
        <p><a href="libreprose.com/reset-password?token=%s">Reset Password</a></p>
        <p>If you didn't request this, please ignore this email.</p>
    `, resetLink)
    
    log.Printf("Sending reset password email to: %s", req.Email)
    if err := sendEmail(req.Email, "Password Reset Request", emailBody); err != nil {
        log.Printf("Error sending reset email: %v", err)
        sendError(w, "Error sending email", http.StatusInternalServerError)
        return
    }

    log.Printf("Successfully sent reset password email to: %s", req.Email)
    sendJSON(w, Response{Status: "success", Message: "Password reset email sent"})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Token    string `json:"token"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        sendError(w, "Error processing password", http.StatusInternalServerError)
        return
    }

    result := users.FindOneAndUpdate(
        context.Background(),
        bson.M{
            "resetToken":  req.Token,
            "resetExpiry": bson.M{"$gt": time.Now()},
        },
        bson.M{
            "$set": bson.M{"password": string(hash)},
            "$unset": bson.M{
                "resetToken":  "",
                "resetExpiry": "",
            },
        },
    )

    if result.Err() != nil {
        sendError(w, "Invalid or expired reset token", http.StatusBadRequest)
        return
    }

    sendJSON(w, Response{Status: "success", Message: "Password reset successful"})
}
func emailLoginHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("Email login request received")
    
    var req struct {
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Error decoding request body: %v", err)
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    log.Printf("Generating OTP for email: %s", req.Email)
    otp := generateOTP()
    expiry := time.Now().Add(50)

    log.Printf("Updating user record with OTP")
    result := users.FindOneAndUpdate(
        context.Background(),
        bson.M{"email": req.Email},
        bson.M{"$set": bson.M{
            "otp":       otp,
            "otpExpiry": expiry,
        }},
    )
    if result.Err() != nil {
        log.Printf("Email not found: %s", req.Email)
        sendError(w, "Email not found", http.StatusNotFound)
        return
    }

    log.Printf("Sending OTP email to: %s", req.Email)
    emailBody := fmt.Sprintf(`
        <h1>Login OTP</h1>
        <p>Your one-time password is: <strong>%s</strong></p>
        <p>This OTP will expire in 5 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
    `, otp)

    if err := sendEmail(req.Email, "Login OTP", emailBody); err != nil {
        log.Printf("Error sending OTP email: %v", err)
        sendError(w, "Error sending OTP", http.StatusInternalServerError)
        return
    }

    log.Printf("OTP sent successfully to: %s", req.Email)
    sendJSON(w, Response{Status: "success", Message: "OTP sent to email"})
}

func verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email string `json:"email"`
        OTP   string `json:"otp"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var user User
    err := users.FindOne(context.Background(), bson.M{
        "email":     req.Email,
        "otp":       req.OTP,
        "otpExpiry": bson.M{"$gt": time.Now()},
    }).Decode(&user)

    if err != nil {
        sendError(w, "Invalid or expired OTP", http.StatusUnauthorized)
        return
    }

    // Clear OTP
    _, err = users.UpdateOne(
        context.Background(),
        bson.M{"email": req.Email},
        bson.M{"$unset": bson.M{"otp": "", "otpExpiry": ""}},
    )

    token, err := generateToken(user.Username)
    if err != nil {
        sendError(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    sendJSON(w, Response{
        Status:  "success",
        Message: "Login successful",
        Data:    LoginResponse{Token: token},
    })
}

func googleAuthHandler(w http.ResponseWriter, r *http.Request) {
    url := googleOauthConfig.AuthCodeURL("state")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    googleToken, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        sendError(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    client := googleOauthConfig.Client(context.Background(), googleToken)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        sendError(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var googleUser struct {
        ID            string `json:"id"`
        Email         string `json:"email"`
        VerifiedEmail bool   `json:"verified_email"`
        Name          string `json:"name"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
        sendError(w, "Failed to decode user info", http.StatusInternalServerError)
        return
    }

    // Find or create user
    var user User
    err = users.FindOne(context.Background(), bson.M{"googleId": googleUser.ID}).Decode(&user)
    if err == mongo.ErrNoDocuments {
        user = User{
            Username: googleUser.Email,
            Email:    googleUser.Email,
            GoogleID: googleUser.ID,
        }
        _, err = users.InsertOne(context.Background(), user)
        if err != nil {
            sendError(w, "Error creating user", http.StatusInternalServerError)
            return
        }
    }

    // Generate JWT
    jwtToken, err := generateToken(user.Username)
    if err != nil {
        sendError(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    // Redirect to frontend with token
    http.Redirect(w, r, fmt.Sprintf("%s/login/callback?token=%s", frontendURL, jwtToken), http.StatusTemporaryRedirect)
}