package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x01)
const checkSumlen = 4
const walletFile = "wallet.dat"

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

type Wallets struct {
	Wallets map[string]*Wallet
}

func NewWallet() (*Wallet, error) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	public := private.PublicKey

	return &Wallet{
		PrivateKey: *private,
		PublicKey:  append(public.X.Bytes(), public.Y.Bytes()...),
	}, nil
}

func HashPublicKey(pubKey []byte) []byte {
	publicSha256 := sha256.Sum256(pubKey)

	Hasher := ripemd160.New()
	_, err := Hasher.Write(publicSha256[:])
	if err != nil {
		log.Panic("write hash error")
	}

	return Hasher.Sum(nil)
}

func (w *Wallet) GetAddress() []byte {
	return nil
}

// NewWallets creates Wallets and fills it from a file if it exists
func NewWallets() (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFromFile()

	return &wallets, err
}

// CreateWallet adds a Wallet to Wallets
func (ws *Wallets) CreateWallet() string {
	wallet, err := NewWallet()
	if err != nil {
		log.Panic("create wallet fail")
	}
	address := wallet.GetAddress()

	ws.Wallets[hex.EncodeToString(address)] = wallet

	return hex.EncodeToString(address)
}

// GetAddresses returns an array of addresses stored in the wallet file
func (w *Wallet) GetAddresses() []byte {
	pubKeyHash := HashPublicKey(w.PublicKey)
	versionedPayload := append([]byte{version}, pubKeyHash...)
	first := sha256.Sum256(versionedPayload)
	second := sha256.Sum256(first[:])
	checkSum := [checkSumlen]byte{}
	copy(checkSum[:], second[:checkSumlen])
	fullPayload := append(versionedPayload, checkSum[:]...)
	address := base58Encode(fullPayload)
	return []byte(address)
}

// GetWallet returns a Wallet by its address
func (ws Wallets) GetWallet(address []byte) Wallet {
	return *ws.Wallets[hex.EncodeToString(address)]
}

// LoadFromFile loads wallets from the file
func (ws *Wallets) LoadFromFile() error {
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err
	}

	fileContent, err := ioutil.ReadFile(walletFile)
	if err != nil {
		log.Panic(err)
	}

	var wallets Wallets
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))
	err = decoder.Decode(&wallets)
	if err != nil {
		log.Panic(err)
	}

	ws.Wallets = wallets.Wallets

	return nil
}

// https://github.com/btcsuite/btcd/blob/master/btcutil/base58/base58.go
func base58Encode(b []byte) string {
	var bigRadix10 = big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58) // 58^10
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	const alphabetIdx0 = '1'

	x := new(big.Int)
	x.SetBytes(b)

	// maximum length of output is log58(2^(8*len(b))) == len(b) * 8 / log(58)
	maxlen := int(float64(len(b))*1.365658237309761) + 1
	answer := make([]byte, 0, maxlen)
	mod := new(big.Int)
	for x.Sign() > 0 {
		// Calculating with big.Int is slow for each iteration.
		//    x, mod = x / 58, x % 58
		//
		// Instead we can try to do as much calculations on int64.
		//    x, mod = x / 58^10, x % 58^10
		//
		// Which will give us mod, which is 10 digit base58 number.
		// We'll loop that 10 times to convert to the answer.

		x.DivMod(x, bigRadix10, mod)
		if x.Sign() == 0 {
			// When x = 0, we need to ensure we don't add any extra zeros.
			m := mod.Int64()
			for m > 0 {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		} else {
			m := mod.Int64()
			for i := 0; i < 10; i++ {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		}
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}

// SaveToFile saves wallets to a file
func (ws Wallets) SaveToFile() {
	var content bytes.Buffer

	gob.Register(elliptic.P256())

	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(ws)
	if err != nil {
		log.Panic(err)
	}

	err = ioutil.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}
