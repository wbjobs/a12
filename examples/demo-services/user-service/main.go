package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var rdb *redis.Client

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		cached, err := rdb.Get(ctx, "users:list").Result()
		
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(cached))
			return
		}

		users := []map[string]interface{}{
			{"id": 1, "name": "Alice"},
			{"id": 2, "name": "Bob"},
			{"id": 3, "name": "Charlie"},
		}

		data, _ := json.Marshal(users)
		rdb.Set(ctx, "users:list", data, 5*time.Minute)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	http.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		id := r.PathValue("id")
		
		user, err := rdb.Get(ctx, "user:"+id).Result()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			user = `{"id": ` + id + `, "name": "User ` + id + `"}`
			rdb.Set(ctx, "user:"+id, user, 5*time.Minute)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(user))
	})

	log.Println("User service starting on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}
