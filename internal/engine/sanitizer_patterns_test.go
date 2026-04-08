package engine

import "testing"

func TestLuhnCheck_ValidVisa(t *testing.T) {
	if !luhnCheck("4532015112830366") {
		t.Fatal("expected valid visa number")
	}
}

func TestLuhnCheck_ValidMastercard(t *testing.T) {
	if !luhnCheck("5555555555554444") {
		t.Fatal("expected valid mastercard number")
	}
}

func TestLuhnCheck_InvalidNumber(t *testing.T) {
	if luhnCheck("4532015112830000") {
		t.Fatal("expected invalid card number")
	}
}

func TestLuhnCheck_AllZeros(t *testing.T) {
	if luhnCheck("0000000000000000") {
		t.Fatal("expected all-zeros string to be rejected")
	}
}

func TestIsValidIPOctet_Valid(t *testing.T) {
	if !isValidIPOctet("255") {
		t.Fatal("expected octet 255 to be valid")
	}
}

func TestIsValidIPOctet_TooLarge(t *testing.T) {
	if isValidIPOctet("256") {
		t.Fatal("expected octet 256 to be invalid")
	}
}
