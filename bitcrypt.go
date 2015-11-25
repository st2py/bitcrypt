package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	var genKey bool
	flag.BoolVar(&genKey, "g", false, "Generate RSA key files")
	var bits int
	flag.IntVar(&bits, "b", 2048, "RSA key length, only valid for 1024, 2048, 4096")
	var keyPath string
	flag.StringVar(&keyPath, "p", "", "RSA key files directory path")

	var encFile bool
	flag.BoolVar(&encFile, "e", false, "Encrypt file")
	var decFile bool
	flag.BoolVar(&decFile, "d", false, "Decrypt file")
	var fileName string
	flag.StringVar(&fileName, "f", "", "Directory/file to encrypt/decrypt")
	var keyFile string
	flag.StringVar(&keyFile, "k", "", "RSA public/private file path")
	var aesLen int
	flag.IntVar(&aesLen, "l", 32, "AES key length for encrypt, only valid for 16, 24, 32")
	var aesCpt string
	flag.StringVar(&aesCpt, "t", "cfb", "AES cipher type for encrypt, only valid for cfb, ctr, ofb")

	flag.Parse()
	//	log.Println("bits:", bits)
	//	log.Println("genKey:", genKey)
	//	log.Println("encFile:", encFile)
	//	log.Println("decFile:", decFile)
	//	log.Println("fileName:", fileName)
	//	log.Println("dirPath:", dirPath)

	relFile, _ := exec.LookPath(os.Args[0])
	selfName := filepath.Base(relFile)
	absFile, _ := filepath.Abs(relFile)
	absPath, _ := filepath.Abs(filepath.Dir(absFile))
	//fmt.Println("selfName:", selfName)

	var err error
	if genKey == true {
		if bits != 1024 && bits != 2048 && bits != 4096 && bits != 8192 {
			log.Fatal("Error: -b only valid for 1024 2048 4096")
		}

		if keyPath == "" {
			keyPath = filepath.Join(absPath, "keys")
		} else {
			if !IsDirExist(keyPath) {
				log.Fatal("Error: path ", keyPath, " isn't exist")
			}
		}

		log.Println("RSA key length", bits)
		log.Println("Directory at", keyPath)
		err = RsaGenKey(keyPath, bits)
		if err != nil {
			log.Println(err.Error())
			log.Fatal("Error: generate RSA key failed")
		}
		log.Println("Generate RSA key OK")
		log.Println("Please backup your RSA key files carefully")
		log.Println("If RSA key files are lost, all encrypted files cannot be decrypted")
	} else if encFile == true || decFile == true {
		if keyFile == "" {
			if encFile == true {
				keyFile = filepath.Join(absPath, "keys", "public.pem")
			} else {
				keyFile = filepath.Join(absPath, "keys", "private.pem")
			}
		}

		if !IsFileExist(keyFile) {
			log.Println("Error: rsa key file", keyFile, "isn't exist")
			log.Fatal("Simply generate RSA key: ", selfName, " -g")
		}

		if !IsFileExist(fileName) && !IsDirExist(fileName) {
			if encFile == true {
				log.Fatal("Error: ", fileName, " to encrypt isn't exist")
			} else {
				log.Fatal("Error: ", fileName, " to decrypt isn't exist")
			}
		}

		bKey := RsaReadKey(keyFile)
		if bKey == nil {
			log.Fatal("Error: read key file ", keyFile, " failed")
		}

		inPath := fileName
		if aesLen != 16 && aesLen != 24 && aesLen != 32 {
			aesLen = 32
		}
		if aesCpt != "cfb" && aesCpt != "ctr" && aesCpt != "ofb" {
			aesCpt = "cfb"
		}

		isDirFlag := false
		if encFile == true {
			if IsDirExist(inPath) {
				isDirFlag = true
				err = EncryptDir(inPath, bKey, aesLen, aesCpt)
			} else {
				outPath := inPath + ".enc"
				err = EncryptFile(inPath, outPath, bKey, aesLen, aesCpt)
			}

			if err != nil {
				log.Println(err.Error())
				log.Fatal("Error: encrypt ", inPath, " failed")
			} else {
				if isDirFlag == true {
					log.Println("Encrypt directory", inPath, "OK")
				} else {
					log.Println("Encrypt file", inPath, "OK")
				}
			}
		} else {
			if IsDirExist(inPath) {
				isDirFlag = true
				err = DecryptDir(inPath, bKey)
			} else {
				outPath := inPath
				if strings.HasSuffix(outPath, ".enc") == true {
					outPath = strings.TrimSuffix(outPath, ".enc")
				}
				err = DecryptFile(inPath, outPath, bKey)
			}

			if err != nil {
				log.Println(err.Error())
				log.Fatal("Error: decrypt ", inPath, " failed")
			} else {
				if isDirFlag == true {
					log.Println("Decrypt directory", inPath, "OK")
				} else {
					log.Println("Decrypt file", inPath, "OK")
				}
			}
		}
	} else {
		flag.PrintDefaults()

		fmt.Println("")
		fmt.Println("")
		fmt.Println("Example 1: generate RSA key files")
		fmt.Println(selfName, "-g -b 2048")
		fmt.Println(selfName, "-g -b 2048 -p some/directory")

		fmt.Println("")
		fmt.Println("Example 2: encrypt file")
		fmt.Println(selfName, "-e -f some/file")
		fmt.Println(selfName, "-e -f some/file -k some/directory/public.pem")

		fmt.Println("")
		fmt.Println("Example 3: decrypt file")
		fmt.Println(selfName, "-d -f some/file")
		fmt.Println(selfName, "-d -f some/file -k some/directory/private.pem")

		fmt.Println("")
		fmt.Println("Example 4: encrypt directory")
		fmt.Println(selfName, "-e -f some/directory")
		fmt.Println(selfName, "-e -f some/directory -k some/directory/public.pem")

		fmt.Println("")
		fmt.Println("Example 5: decrypt directory")
		fmt.Println(selfName, "-d -f some/directory")
		fmt.Println(selfName, "-d -f some/directory -k some/directory/private.pem")
		fmt.Println("")
	}
}
