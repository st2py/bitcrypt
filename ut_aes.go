package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

func AesEncryptFd(inFile, outFile *os.File, key, iv []byte, ctp int) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	var stream cipher.Stream
	switch ctp {
	case 1:
		stream = cipher.NewCFBEncrypter(block, iv[:])
	case 2:
		stream = cipher.NewCTR(block, iv[:])
	default:
		stream = cipher.NewOFB(block, iv[:])
	}

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.
	return nil
}

func AesDecryptFd(inFile, outFile *os.File, key, iv []byte, ctp int) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	var stream cipher.Stream
	switch ctp {
	case 1:
		stream = cipher.NewCFBDecrypter(block, iv[:])
	case 2:
		stream = cipher.NewCTR(block, iv[:])
	default:
		stream = cipher.NewOFB(block, iv[:])
	}

	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return err
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
	return nil
}

func AesEncryptFile(inPath, outPath string, key, iv []byte, aesCtp string) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var ctp int
	switch aesCtp {
	case "cfb":
		ctp = 1
	case "ctr":
		ctp = 2
	default:
		ctp = 4
	}

	return AesEncryptFd(inFile, outFile, key, iv, ctp)
}

func AesDecryptFile(inPath, outPath string, key, iv []byte, aesCtp string) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var ctp int
	switch aesCtp {
	case "cfb":
		ctp = 1
	case "ctr":
		ctp = 2
	default:
		ctp = 4
	}

	return AesDecryptFd(inFile, outFile, key, iv, ctp)
}

func AesEncryptData(data, key []byte, ctp string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	data_enc := make([]byte, aes.BlockSize+len(data))
	iv := data_enc[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}

	var stream cipher.Stream
	switch ctp {
	case "cfb":
		stream = cipher.NewCFBEncrypter(block, iv)
	case "ctr":
		stream = cipher.NewCTR(block, iv)
	default:
		stream = cipher.NewOFB(block, iv)
	}
	stream.XORKeyStream(data_enc[aes.BlockSize:], data)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return data_enc
}

func AesDecryptData(data, key []byte, ctp string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	if len(data) < aes.BlockSize {
		return nil
	}

	iv := data[:aes.BlockSize]
	data_dec := data[aes.BlockSize:]

	var stream cipher.Stream
	switch ctp {
	case "cfb":
		stream = cipher.NewCFBDecrypter(block, iv)
	case "ctr":
		stream = cipher.NewCTR(block, iv)
	default:
		stream = cipher.NewOFB(block, iv)
	}

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(data_dec, data_dec)
	return data_dec
}

func AesDataTest(key string) {
	bkey := []byte(key)
	plaintext := []byte("some plain text for test")
	fmt.Println("==================== AesDataTest ====================")

	ciphertext := AesEncryptData(plaintext, bkey, "cfb")
	fmt.Println("CFB ENC:", hex.EncodeToString(ciphertext))
	bDec := AesDecryptData(ciphertext, bkey, "cfb")
	fmt.Println("CFB DEC:", string(bDec))

	ciphertext = AesEncryptData(plaintext, bkey, "ctr")
	fmt.Println("CTR ENC:", hex.EncodeToString(ciphertext))
	bDec = AesDecryptData(ciphertext, bkey, "ctr")
	fmt.Println("CTR DEC:", string(bDec))

	ciphertext = AesEncryptData(plaintext, bkey, "ofb")
	fmt.Println("OFB ENC:", hex.EncodeToString(ciphertext))
	bDec = AesDecryptData(ciphertext, bkey, "ofb")
	fmt.Println("OFB DEC:", string(bDec))
}

func AesFileTest(key string) {
	var iv [16]byte
	fmt.Println("==================== AesFileTest ====================")

	start := time.Now()
	AesEncryptFile("big.dat", "big.dat.enc", []byte(key), iv[:], "cfb")
	dis := time.Now().Sub(start).Seconds()
	fmt.Println("CFB ENC Time:", dis)

	start = time.Now()
	AesDecryptFile("big.dat.enc", "big.dat.dec", []byte(key), iv[:], "cfb")
	dis = time.Now().Sub(start).Seconds()
	fmt.Println("CFB DEC Time:", dis)

	start = time.Now()
	AesEncryptFile("big.dat", "big.dat.enc", []byte(key), iv[:], "ctr")
	dis = time.Now().Sub(start).Seconds()
	fmt.Println("CTR ENC Time:", dis)

	start = time.Now()
	AesDecryptFile("big.dat.enc", "big.dat.dec", []byte(key), iv[:], "ctr")
	dis = time.Now().Sub(start).Seconds()
	fmt.Println("CTR DEC Time:", dis)

	start = time.Now()
	AesEncryptFile("big.dat", "big.dat.enc", []byte(key), iv[:], "ofb")
	dis = time.Now().Sub(start).Seconds()
	fmt.Println("OFB ENC Time:", dis)

	start = time.Now()
	AesDecryptFile("big.dat.enc", "big.dat.dec", []byte(key), iv[:], "ofb")
	dis = time.Now().Sub(start).Seconds()
	fmt.Println("OFB DEC Time:", dis)
}
