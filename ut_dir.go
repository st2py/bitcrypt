package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func IsDirExist(path string) bool {
	fi, err := os.Stat(path)

	if err != nil {
		return os.IsExist(err)
	}

	return fi.IsDir()
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

func EncryptDir(srcDir string, rsaPubKey []byte, aesBits int, aesCtp string) error {
	srcDir, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}

	dstDir := filepath.Join(filepath.Dir(srcDir), filepath.Base(srcDir)+"_enc")
	//fmt.Println("srcDir:", srcDir)
	//fmt.Println("dstDir:", dstDir)

	err = filepath.Walk(srcDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		encPath := filepath.Join(dstDir, relPath)
		if strings.Contains(encPath, ".git") || strings.Contains(encPath, ".svn") {
			return nil
		}

		if f.IsDir() {
			if !IsDirExist(encPath) {
				mode := f.Mode().Perm()
				//fmt.Println("Mode:", mode)
				//fmt.Println(path, " -> ", encPath)
				err = os.Mkdir(encPath, mode)
			}
		} else {
			outPath := encPath + ".enc"
			//fmt.Println(path, " -> ", outPath)
			err = EncryptFile(path, outPath, rsaPubKey, aesBits, aesCtp)
		}

		if err != nil {
			log.Println("Error for encryption:", path)
			log.Println(err.Error())
		}
		return nil
	})

	return err

}

func DecryptDir(srcDir string, rsaPriKey []byte) error {
	srcDir, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}

	dstDir := srcDir
	if strings.HasSuffix(dstDir, "_enc") == true {
		dstDir = strings.TrimSuffix(dstDir, "_enc")
	}

	//fmt.Println("srcDir:", srcDir)
	//fmt.Println("dstDir:", dstDir)

	err = filepath.Walk(srcDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		decPath := filepath.Join(dstDir, relPath)
		if f.IsDir() {
			if !IsDirExist(decPath) {
				mode := f.Mode().Perm()
				//fmt.Println("Mode:", mode)
				//fmt.Println(path, " -> ", decPath)
				err = os.Mkdir(decPath, mode)
			}
		} else {
			outPath := decPath
			if strings.HasSuffix(outPath, ".enc") == true {
				outPath = strings.TrimSuffix(outPath, ".enc")
			}
			//fmt.Println(path, " -> ", outPath)
			err = DecryptFile(path, outPath, rsaPriKey)
		}

		if err != nil {
			log.Println("Error for decryption:", path)
			log.Println(err.Error())
		}
		return nil
	})

	return err
}

func test_dir(srcDir string) error {
	var dstDir string

	dstDir = filepath.Join(filepath.Dir(srcDir), filepath.Base(srcDir)+"_enc")

	fmt.Println("srcDir:", srcDir)
	fmt.Println("dstDir:", dstDir)

	err := filepath.Walk(srcDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}

		relPath, _ := filepath.Rel(srcDir, path)
		encPath := filepath.Join(dstDir, relPath)
		fmt.Println(path, " -> ", encPath)

		if f.IsDir() {
			mode := f.Mode().Perm()
			fmt.Println("Mode:", mode)
			os.Mkdir(encPath, mode)
			return nil
		}

		return nil
	})

	if err != nil {
		fmt.Printf("filepath.Walk() returned %v\n", err)
	}

	return nil
}
