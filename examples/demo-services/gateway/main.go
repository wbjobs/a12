package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	userServiceURL := os.Getenv("USER_SERVICE_URL")
	orderServiceURL := os.Getenv("ORDER_SERVICE_URL")

	if userServiceURL == "" {
		userServiceURL = "http://localhost:8082"
	}
	if orderServiceURL == "" {
		orderServiceURL = "http://localhost:8083"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(userServiceURL + "/users")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	http.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(orderServiceURL + "/orders")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	http.HandleFunc("/api/user-orders", func(w http.ResponseWriter, r *http.Request) {
		resp1, err := client.Get(userServiceURL + "/users/123")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp1.Body.Close()

		resp2, err := client.Get(orderServiceURL + "/orders?user=123")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp2.Body.Close()

		body, _ := io.ReadAll(resp2.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp2.StatusCode)
		w.Write(body)
	})

	log.Println("Gateway service starting on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
