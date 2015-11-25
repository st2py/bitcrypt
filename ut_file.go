package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	//"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// 32 bytes
type HdrInfo struct {
	Rlen int32    // AesInfo size after RSA
	Eflg uint32   // encrypted file flag 0x32571235
	Mdtm int64    // file modify time before encrypted
	Fchk [16]byte // file md5 checksum before encrypted
}

// 128 bytes
type AesInfo struct {
	Rand [40]byte // security random data
	Size uint32   // aes key size 16 24 32
	Type uint32   // aes cipher type 1 - cfb, 2 - ctr, 4 - ofb
	Fchk [16]byte // file md5 checksum before encrypted

	Aesv [32]byte // aes iv
	Aesk [32]byte // aes key
}

func CalcFchk(inFile *os.File) []byte {
	h := md5.New()
	io.Copy(h, inFile)
	inFile.Seek(0, 0)
	return h.Sum(nil)
}

func CheckFchk(a, b []byte) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Uint32ToBytes(i uint32) []byte {
	var buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, i)
	return buf
}

func BytesToUint32(buf []byte) uint32 {
	return uint32(binary.LittleEndian.Uint32(buf))
}

func AesInfo2Bytes(info *AesInfo) []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, info)
	if err != nil {
		return nil
	}

	//fmt.Println(hex.EncodeToString(buf.Bytes()))
	return buf.Bytes()
}

func Bytes2AesInfo(b []byte) *AesInfo {
	info := new(AesInfo)

	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, info)
	if err != nil {
		return nil
	}
	return info
}

func HdrInfo2Bytes(info *HdrInfo) []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, info)
	if err != nil {
		return nil
	}

	//fmt.Println(hex.EncodeToString(buf.Bytes()))
	return buf.Bytes()
}

func Bytes2HdrInfo(b []byte) *HdrInfo {
	info := new(HdrInfo)

	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, info)
	if err != nil {
		return nil
	}
	return info
}

func GenEncHdr(inFile *os.File, aesBits int, aesCtp string) (*HdrInfo, *AesInfo) {
	hdrf := new(HdrInfo)
	info := new(AesInfo)

	if hdrf == nil || info == nil {
		return nil, nil
	}
	if _, err := io.ReadFull(rand.Reader, info.Rand[:]); err != nil {
		return nil, nil
	}

	if _, err := io.ReadFull(rand.Reader, info.Aesv[:]); err != nil {
		return nil, nil
	}
	//fmt.Println("Aesv:", hex.EncodeToString(info.Aesv[:]))

	if _, err := io.ReadFull(rand.Reader, info.Aesk[:]); err != nil {
		return nil, nil
	}

	fileInfo, err := inFile.Stat()
	if err != nil {
		return nil, nil
	}
	hdrf.Eflg = 0x32571235
	hdrf.Mdtm = fileInfo.ModTime().Unix()
	//fmt.Println("Mdtm:", fileInfo.ModTime().String())
	//fmt.Println("Mdtm:", hdrf.Mdtm)

	if aesBits != 16 && aesBits != 24 && aesBits != 32 {
		aesBits = 32
	}
	info.Size = uint32(aesBits)
	switch aesCtp {
	case "cfb":
		info.Type = 1
	case "ctr":
		info.Type = 2
	default:
		info.Type = 4
	}

	fchk := CalcFchk(inFile)
	copy(hdrf.Fchk[:], fchk)
	copy(info.Fchk[:], fchk)
	//fmt.Println("Fchk:", hex.EncodeToString(info.Fchk[:]))
	//fmt.Println("Aesk:", hex.EncodeToString(info.Aesk[:]))

	return hdrf, info
}

func ReadHdrInfo(inPath string) (*HdrInfo, *os.File, error) {
	inFile, err := os.Open(inPath)
	if err != nil {
		return nil, nil, err
	}

	inInfo, err := inFile.Stat()
	if err != nil {
		return nil, nil, err
	}
	if inInfo.Size() < int64(160) {
		return nil, nil, errors.New("not an encrypted file error")
	}

	var buf = make([]byte, binary.Size(HdrInfo{}))
	_, err = inFile.Read(buf)
	if err != nil {
		return nil, nil, err
	}

	hdrf := Bytes2HdrInfo(buf)
	return hdrf, inFile, nil
}

func ReadEncHdr(inPath string, rsaPriKey []byte) (*HdrInfo, *AesInfo, *os.File, error) {
	hdrf, inFile, err := ReadHdrInfo(inPath)
	if err != nil {
		return nil, nil, nil, err
	}

	var rsaBin = make([]byte, hdrf.Rlen)
	_, err = inFile.Read(rsaBin)
	if err != nil {
		return nil, nil, nil, errors.New("read rsa bin failed")
	}

	binInfo, err := RsaDecrypt(rsaPriKey, rsaBin)
	if binInfo == nil {
		return nil, nil, nil, errors.New("decrypt rsa bin failed")
	}

	info := Bytes2AesInfo(binInfo)
	if CheckFchk(hdrf.Fchk[:], info.Fchk[:]) != true {
		return nil, nil, nil, errors.New("header checksum failed")
	}

	//fmt.Println("binInfo len:", len(binInfo))
	//fmt.Println("binInfo:", hex.EncodeToString(binInfo))

	return hdrf, info, inFile, nil
}

func IsNewEnc(inPath string, info *HdrInfo) bool {
	hdrf, _, err := ReadHdrInfo(inPath)
	if err != nil {
		return true
	}

	//fmt.Println("hdrf:", hex.EncodeToString(hdrf.Fchk[:]))
	//fmt.Println("info:", hex.EncodeToString(info.Fchk[:]))

	return !CheckFchk(hdrf.Fchk[:], info.Fchk[:])
}

func IsNewDec(inPath string, info *HdrInfo) bool {
	inFile, err := os.Open(inPath)
	if err != nil {
		return true
	}
	defer inFile.Close()

	fchk := CalcFchk(inFile)

	//fmt.Println("fchk:", hex.EncodeToString(fchk[:]))
	//fmt.Println("info:", hex.EncodeToString(info.Fchk[:]))
	return !CheckFchk(info.Fchk[:], fchk[:])
}

func EncryptFile(inPath, outPath string, rsaPubKey []byte, aesBits int, aesCtp string) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	hdrf, info := GenEncHdr(inFile, aesBits, aesCtp)
	if info == nil {
		return errors.New("gen file header failed")
	}

	if IsFileExist(outPath) && !IsNewEnc(outPath, hdrf) {
		return errors.New("file already encrypted and not modified")
	}

	outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	binInfo := AesInfo2Bytes(info)
	//fmt.Println("binInfo len:", len(binInfo))
	//fmt.Println("binInfo:", hex.EncodeToString(binInfo))

	rsaBin, err := RsaEncrypt(rsaPubKey, binInfo)
	if err != nil {
		return err
	}

	hdrf.Rlen = int32(len(rsaBin))
	//fmt.Println("rsaLen:", hdrf.Rlen)
	//fmt.Println("rsaBin:", hex.EncodeToString(rsaBin))

	_, err = outFile.Write(HdrInfo2Bytes(hdrf))
	if err != nil {
		return err
	}

	_, err = outFile.Write(rsaBin)
	if err != nil {
		return err
	}

	key := info.Aesk[:info.Size]
	aiv := info.Aesv[:aes.BlockSize]
	return AesEncryptFd(inFile, outFile, key, aiv, int(info.Type))
}

func DecryptFile(inPath, outPath string, rsaPriKey []byte) error {
	hdrf, info, inFile, err := ReadEncHdr(inPath, rsaPriKey)
	if err != nil {
		return err
	}
	defer inFile.Close()

	if hdrf.Eflg != 0x32571235 {
		return errors.New("not an encrypted file error")
	}

	if IsFileExist(outPath) && !IsNewDec(outPath, hdrf) {
		return errors.New("file already decrypted and not modified")
	}

	hdrLen := int64(hdrf.Rlen + int32(binary.Size(HdrInfo{})))
	_, err = inFile.Seek(hdrLen, 0)
	if err != nil {
		return err
	}

	outPath2 := outPath + ".dec"
	outFile, err := os.OpenFile(outPath2, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	key := info.Aesk[:info.Size]
	aiv := info.Aesv[:aes.BlockSize]
	err = AesDecryptFd(inFile, outFile, key, aiv, int(info.Type))
	if err != nil {
		return err
	}

	outFile.Close()
	if IsNewDec(outPath2, hdrf) {
		return errors.New("decrypted file checksum not match")
	} else {
		os.Remove(outPath)
		err = os.Rename(outPath2, outPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func EncryptFileTest() {
	fmt.Println("==================== EncryptFileTest ====================")

	relFile, _ := exec.LookPath(os.Args[0])
	absFile, _ := filepath.Abs(relFile)
	absPath, _ := filepath.Abs(filepath.Dir(absFile))
	keyPath := filepath.Join(absPath, "keys")

	publicKey := RsaReadKey(filepath.Join(keyPath, "public.pem"))
	if publicKey == nil {
		fmt.Println("RsaReadKey public.pem failed")
		return
	}

	err := EncryptFile("big.dat", "big.dat.enc", publicKey, 16, "cfb")
	if err != nil {
		fmt.Println("EncryptFile failed")
		return
	}
}

func DecryptFileTest() {
	fmt.Println("==================== DecryptFileTest ====================")

	relFile, _ := exec.LookPath(os.Args[0])
	absFile, _ := filepath.Abs(relFile)
	absPath, _ := filepath.Abs(filepath.Dir(absFile))
	keyPath := filepath.Join(absPath, "keys")

	privateKey := RsaReadKey(filepath.Join(keyPath, "private.pem"))
	if privateKey == nil {
		fmt.Println("RsaReadKey private.pem failed")
		return
	}

	err := DecryptFile("big.dat.enc", "big.dat.dec", privateKey)
	if err != nil {
		fmt.Println("DecryptFile failed")
		return
	}
}
