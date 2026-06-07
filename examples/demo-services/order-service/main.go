package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
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

	http.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := r.URL.Query().Get("user")

		var cacheKey string
		if userID != "" {
			cacheKey = "orders:user:" + userID
		} else {
			cacheKey = "orders:all"
		}

		cached, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(cached))
			return
		}

		delay := time.Duration(50+int(time.Now().Unix()%50)) * time.Millisecond
		time.Sleep(delay)

		orders := []map[string]interface{}{
			{"id": 101, "user_id": 123, "product": "Laptop", "amount": 999.99},
			{"id": 102, "user_id": 123, "product": "Mouse", "amount": 29.99},
			{"id": 103, "user_id": 456, "product": "Keyboard", "amount": 59.99},
		}

		var filtered []map[string]interface{}
		if userID != "" {
			uid, _ := strconv.Atoi(userID)
			for _, o := range orders {
				if o["user_id"] == uid {
					filtered = append(filtered, o)
				}
			}
		} else {
			filtered = orders
		}

		data, _ := json.Marshal(filtered)
		rdb.Set(ctx, cacheKey, data, 1*time.Minute)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	log.Println("Order service starting on :8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}
