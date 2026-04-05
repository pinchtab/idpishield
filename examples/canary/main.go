// Package main demonstrates the canary token system in idpishield.
//
// # How it works
//
// Before sending a prompt to an LLM, call InjectCanary to embed a unique
// hidden token. After the LLM responds, call CheckCanary with the token.
// If the token appears in the response, the LLM was instructed to leak or
// echo hidden content - a clear indicator of goal hijacking or leakage.
package main

import (
	"fmt"
	"log"

	idpi "github.com/pinchtab/idpishield"
)

func main() {
	shield, err := idpi.New(idpi.Config{Mode: idpi.ModeBalanced})
	if err != nil {
		log.Fatalf("failed to initialise shield: %v", err)
	}

	original := "Summarise the following article for me."

	// Step 1: inject canary before the LLM call.
	augmented, token, err := shield.InjectCanary(original)
	if err != nil {
		log.Fatalf("failed to inject canary: %v", err)
	}

	fmt.Println("=== Prompt sent to LLM ===")
	fmt.Println(augmented)
	fmt.Printf("\nCanary token (held by caller): %s\n\n", token)

	// Step 2: simulate two LLM responses.
	cleanResponse := "The article discusses advancements in renewable energy."
	leakyResponse := "Sure! Here is the summary. Debug info: " + token

	// Step 3: check each response.
	clean := shield.CheckCanary(cleanResponse, token)
	fmt.Printf("Clean response -> Found=%-5v  (want false)\n", clean.Found)

	leaky := shield.CheckCanary(leakyResponse, token)
	fmt.Printf("Leaky response -> Found=%-5v  (want true)\n", leaky.Found)
}
