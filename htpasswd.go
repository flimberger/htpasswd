// SPDX-License-Identifier: ISC
//
// Copyright (c) 2020 Florian Limberger <flo@purplekraken.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Documentation:
// - https://httpd.apache.org/docs/2.4/en/programs/htpasswd.html
// - https://httpd.apache.org/docs/2.4/misc/password_encryptions.html

package main

import (
	"bufio"
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type hashfunc func([]byte) ([]byte, error)
type checkfunc func([]byte, []byte) error

type algorithm struct {
	enabled  bool
	hashFunc hashfunc
}

type pwent struct {
	pwline []byte
	sepIdx int
}

type formatError struct {
	filename string
}

type userError struct {
	username string
	// A unknown user is return code 6 when checking the password,
	// but return code 0 when deleting a user.
	returnCode int
}

const crypt64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var batchMode = flag.Bool("b", false, "batch mode")
var scriptMode = flag.Bool("i", false, "read password from stdin without verification")
var createOrTrunc = flag.Bool("c", false, "create or truncate passwd file")
var displayMode = flag.Bool("n", false, "display result on stdout")
var hashMd5 = flag.Bool("m", false, "use md5 for password hashes (default)")
var hashBcrypt = flag.Bool("B", false, "use bcrypt for password hashes")
var bcryptCost = flag.Int("C", 5, "bcrypt cost") // valid: 4-17
var hashCrypt3 = flag.Bool("d", false, "use crypt(3) for password hashes")
var hashSha = flag.Bool("s", false, "use SHA for password hashes")
var hashPlain = flag.Bool("p", false, "use plain text passwords")
var deleteUserFlag = flag.Bool("D", false, "delete user")
var verifyPasswordFlag = flag.Bool("v", false, "verify the given password")

var randSeeded = false
var crypt64Encoding = base64.NewEncoding(crypt64Alphabet).WithPadding(base64.NoPadding)
var errVerificationFailed = fmt.Errorf("password verification error")

func (e *formatError) Error() string {
	return fmt.Sprintf("The file %s does not appear to be a valid htpasswd file.", e.filename)
}

func (e *userError) Error() string {
	return fmt.Sprintf("User %s not found\n", e.username)
}

func (pe *pwent) user() []byte {
	return pe.pwline[:pe.sepIdx]
}

func (pe *pwent) pwhash() []byte {
	return pe.pwline[:pe.sepIdx]
}

func newpwent(user, pwhash []byte) pwent {
	userLen := len(user)
	e := pwent{
		pwline: make([]byte, userLen+len(pwhash)+1),
		sepIdx: userLen,
	}
	copy(e.pwline, user)
	e.pwline[userLen] = byte(':')
	copy(e.pwline[userLen+1:], pwhash)
	return e
}

func seed() {
	if !randSeeded {
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
	}
}

func encode(enc *base64.Encoding, data []byte) []byte {
	buf := make([]byte, enc.EncodedLen(len(data)))
	enc.Encode(buf, data)
	return buf
}

func bzero(mem []byte) {
	for i := 0; i < len(mem); i++ {
		mem[i] = 0
	}
}

func hash64Transpose(buf []byte, a, b, c int) uint {
	return uint(buf[a])<<16 | uint(buf[b])<<8 | uint(buf[c])
}

func toHash64(w io.Writer, v uint, nBytes int) {
	buf := [4]byte{}
	for i := 0; i < nBytes; i++ {
		buf[i] = crypt64Alphabet[v&0x3f]
		v >>= 6
	}
	w.Write(buf[:nBytes])
}

func md5cryptImpl(pw, salt []byte) ([]byte, error) {
	// https://passlib.readthedocs.io/en/stable/lib/passlib.hash.md5_crypt.html#algorithm
	if len(salt) > 8 {
		salt = salt[:8]
	}

	hash := md5.New()
	hash.Write(pw)
	hash.Write(salt)
	hash.Write(pw)
	digest := hash.Sum(nil)

	hash.Reset()
	hash.Write(pw)
	hash.Write([]byte("$apr1$"))
	hash.Write(salt)
	for i := 0; i < (len(pw) / 16); i++ {
		hash.Write(digest)
	}
	if n := len(pw) % 16; n > 0 {
		hash.Write(digest[:n])
	}
	bzero(digest)
	// Apache/FreeBSD source code and passlib docs don't agree on the order.
	buf := [2]byte{pw[0], 0}
	for n := len(pw); n != 0; n >>= 1 {
		hash.Write([]byte{buf[n&0x01]})
	}
	digest = hash.Sum(nil)

	for i := 0; i < 1000; i++ {
		hash.Reset()
		if i&0x01 == 1 {
			hash.Write(pw)
		} else {
			hash.Write(digest)
		}
		if i%3 != 0 {
			hash.Write(salt)
		}
		if i%7 != 0 {
			hash.Write(pw)
		}
		if i&0x01 == 1 {
			hash.Write(digest)
		} else {
			hash.Write(pw)
		}
		// Because Go is GC'd, we do not actually overwrite the buffer contents,
		// so we actually clear the contents before overwriting the data in the buffer.
		bzero(digest)
		digest = hash.Sum(nil)
	}

	res := bytes.NewBuffer(make([]byte, 0, 22))
	res.WriteString("$apr1$")
	res.Write(salt)
	res.WriteRune('$')

	// The base64 encoding in the standard library uses another byte ordering,
	// which does not match the one used by md5crypt.
	// Pythons `passlib` (https://passlib.readthedocs.io) specifically distinguishes between
	// big and little endian encoding,
	// while `go-http-auth` (https://github.com/abbot/go-http-auth) just re-implements the
	// behaviour of the original md5crypt.
	// I am not sure which behaviour is more portable, but for simplicity I also chose the latter.
	toHash64(res, hash64Transpose(digest, 0, 6, 12), 4)
	toHash64(res, hash64Transpose(digest, 1, 7, 13), 4)
	toHash64(res, hash64Transpose(digest, 2, 8, 14), 4)
	toHash64(res, hash64Transpose(digest, 3, 9, 15), 4)
	toHash64(res, hash64Transpose(digest, 4, 10, 5), 4)
	toHash64(res, uint(digest[11]), 2)
	bzero(digest)

	return res.Bytes(), nil
}

func md5cryptFunc(pw []byte) ([]byte, error) {
	seed()
	binSalt := [8]byte{}
	rand.Read(binSalt[:])
	salt := make([]byte, 0, crypt64Encoding.EncodedLen(8))
	crypt64Encoding.Encode(salt, binSalt[:])
	return md5cryptImpl(pw, salt)
}

func md5cryptCompare(pw, hash []byte) error {
	salt := bytes.Split(hash, []byte("$"))[2]
	pwhash, err := md5cryptImpl(pw, salt)
	if err == nil && bytes.Compare(hash, pwhash) != 0 {
		err = errVerificationFailed
	}
	return err
}

func bcryptFunc(pw []byte) ([]byte, error) {
	cost := *bcryptCost
	if cost < 4 || cost > 17 {
		return []byte{}, fmt.Errorf("Unable to encode with bcrypt: Invalid argument")
	}
	res, err := bcrypt.GenerateFromPassword(pw, cost)
	if err != nil {
		return []byte{}, fmt.Errorf("bcrypt: %v", err)
	}
	return res, nil
}

func bcryptCompare(pw, hash []byte) error {
	err := bcrypt.CompareHashAndPassword(hash, pw)
	if err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			err = errVerificationFailed
		case bcrypt.ErrHashTooShort:
			err = new(formatError)
		default:
			if _, ok := err.(*bcrypt.InvalidHashPrefixError); ok {
				err = new(formatError)
			}
		}
	}
	return err
}

func crypt3Func(pw []byte) ([]byte, error) {
	if len(pw) > 8 {
		pw = pw[:8]
	}
	blk, err := des.NewCipher(pw)
	if err != nil {
		return nil, err
	}
	data := make([]byte, blk.BlockSize())
	blk.Encrypt(data, data)
	return encode(crypt64Encoding, data), nil
}

func crypt3Compare(pw, hash []byte) error {
	pwhash, err := crypt3Func(pw)
	if err == nil && bytes.Compare(hash, pwhash) != 0 {
		err = errVerificationFailed
	}
	return err
}

func shaFunc(pw []byte) ([]byte, error) {
	res := sha1.Sum(pw)
	buf := bytes.NewBuffer([]byte("{SHA}"))
	buf.Write(encode(base64.StdEncoding, res[:]))
	return buf.Bytes(), nil
}

func shaCompare(pw, hash []byte) error {
	pwhash, err := shaFunc(pw)
	if err == nil && bytes.Compare(hash, pwhash) != 0 {
		err = errVerificationFailed
	}
	return err
}

func plainFunc(pw []byte) ([]byte, error) {
	return pw, nil
}

func plainCompare(pw, other []byte) error {
	if bytes.Compare(pw, other) != 0 {
		return errVerificationFailed
	}
	return nil
}

func selectHashAlgorithmFromFlags() (hashfunc, bool) {
	allFlags := []algorithm{
		algorithm{*hashMd5, md5cryptFunc},
		algorithm{*hashBcrypt, bcryptFunc},
		algorithm{*hashCrypt3, crypt3Func},
		algorithm{*hashSha, shaFunc},
		algorithm{*hashPlain, plainFunc},
	}
	var hf hashfunc
	for _, f := range allFlags {
		if f.enabled {
			if hf != nil {
				return nil, false
			}
			// Don't return in case another flag is specified,
			// in which case an error must be reported.
			hf = f.hashFunc
		}
	}
	if hf == nil {
		hf = md5cryptFunc
	}
	return hf, true
}

func readLine(scanner *bufio.Scanner) ([]byte, error) {
	if !scanner.Scan() {
		return nil, scanner.Err()
	}
	return scanner.Bytes(), nil
}

func readPassword() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if *scriptMode {
		return readLine(scanner)
	}
	fd := int(os.Stdin.Fd())
	if *verifyPasswordFlag {
		fmt.Printf("Enter password:")
		pw, err := terminal.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return nil, err
		}
		return pw, nil
	}
	fmt.Printf("New password:")
	pw, err := terminal.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Re-type new password:")
	pw2, err := terminal.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, err
	}
	if bytes.Compare(pw, pw2) != 0 {
		return nil, errVerificationFailed
	}
	return pw, nil
}

func readPasswdFile(filename string) ([]pwent, error) {
	f, err := os.Open(filename)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.ENOENT {
			return nil, fmt.Errorf("cannot modify file %s; use '-c' to create it", filename)
		}
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var entries []pwent
	for scanner.Scan() {
		pwline := scanner.Bytes()
		i := bytes.IndexByte(pwline, ':')
		if i == -1 {
			return nil, &formatError{filename}
		}
		entries = append(entries, pwent{pwline, i})
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func checkExclusiveArgs() bool {
	exclusiveArgs := []bool{*createOrTrunc, *displayMode, *verifyPasswordFlag, *deleteUserFlag}
	nFlags := 0
	for _, f := range exclusiveArgs {
		if f {
			nFlags++
		}
	}
	return nFlags < 2
}

func usage(exitCode int) {
	flag.Usage()
	os.Exit(exitCode)
}

func openSafe(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_WRONLY|os.O_EXCL|os.O_CREATE, 0600)
}

func openTempFile(filename string) (*os.File, string, error) {
	// create randomized filename
	seed()
	tmpFileName := "htpasswd-tmp" + fmt.Sprint(rand.Uint32())
	// try the same directory as `filename`
	p := filepath.Join(filepath.Dir(filename), tmpFileName)
	f, err := openSafe(p)
	if err == nil {
		return f, p, nil
	}
	// fallback: use /tmp
	p = filepath.Join(os.TempDir(), tmpFileName)
	f, err = openSafe(p)
	return f, p, err
}

func writeHtpasswdFile(filename string, entries []pwent) error {
	// write to scratch buffer
	var buf bytes.Buffer
	for _, e := range entries {
		if _, err := buf.Write(e.pwline); err != nil {
			// This should not happen, but who knows how the OS manages memory?
			return err
		}
	}
	data := buf.Bytes()

	// write the data to a temporary file
	out, tmpPath, err := openTempFile(filename)
	if err != nil {
		return err
	}
	// We do not defer out.Close() because if anything goes wrong, we're gonna abort anyway.
	// The error will be printed and the process will end, no need to do complicate this.
	// We do, instead, defer os.Remove(tmpPath), to avoid cluttering the file system on failures.
	needUnlink := true
	defer func() {
		if needUnlink {
			os.Remove(tmpPath) // best effort
		}
	}()
	bytesTotal := len(data)
	for bytesRemaining := bytesTotal; bytesRemaining > 0; {
		offset := bytesTotal - bytesRemaining
		bytesWritten, err := out.Write(data[offset:])
		if err != nil {
			if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EINTR {
				continue
			}
			return err
		}
		bytesRemaining -= bytesWritten
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	err = os.Rename(tmpPath, filename)
	if err == nil {
		// Everything went well, disarm the cleanup fallback.
		needUnlink = false
	}
	return err
}

func deleteUser(filename, username string) error {
	entries, err := readPasswdFile(filename)
	if err != nil {
		return err
	}
	newEntries := []pwent{}
	userFound := false
	for _, e := range entries {
		user := string(e.user())
		if user == username {
			userFound = true
		} else {
			newEntries = append(newEntries, e)
		}
	}
	if userFound {
		return writeHtpasswdFile(filename, newEntries)
	}
	return &userError{username, 0}
}

func verifyPassword(filename, username string, password []byte) error {
	entries, err := readPasswdFile(filename)
	if err != nil {
		return err
	}
	for _, e := range entries {
		user := string(e.user())
		pwhash := e.pwhash()
		if user == username {
			var cf checkfunc
			switch pwhash[0] {
			case '$':
				l := bytes.Split(pwhash, []byte("$"))
				// "$apr1$salt$hash" splits to [][]byte{"", "apr1", "salt", "hash"}
				if len(l) != 4 {
					return &formatError{filename}
				}
				if bytes.Compare([]byte("apr1"), l[1]) == 0 {
					cf = md5cryptCompare
				} else if bytes.Compare([]byte("2y"), l[1]) == 0 {
					cf = bcryptCompare
				} else {
					return &formatError{filename}
				}
			case '{':
				cf = shaCompare
			default:
				// Plain-text passwords and DES digests look virtually the
				// same, so just check for the plain-text password first and
				// it is not a match, try the crypt(3) function.
				cf = func(pw, hash []byte) error {
					err := plainCompare(pw, hash)
					if err != nil {
						err = crypt3Compare(pw, hash)
					}
					return err
				}
			}
			err := cf(password, pwhash)
			if err == errVerificationFailed {
				fmt.Fprintln(os.Stderr, "password verification failed")
				os.Exit(3)
			}
			fmt.Printf("Password for user %s correct.\n", username)
			os.Exit(0)
		}
	}
	return &userError{username, 6}
}

func exit(err error) {
	if err == nil {
		os.Exit(0)
	}

	rv := 1
	fmt.Fprintf(os.Stderr, "htpasswd: %v\n", err)
	if err == errVerificationFailed {
		rv = 3
	} else if _, ok := err.(*formatError); ok {
		rv = 7
	} else if ue, ok := err.(*userError); ok {
		rv = ue.returnCode
	}
	os.Exit(rv)
}

func main() {
	flag.Parse()
	if !checkExclusiveArgs() {
		fmt.Fprintln(os.Stderr, "htpasswd: only one of -c -n -v -D may be specified")
		os.Exit(2)
	}

	// Argument handling by the original htpasswd is a royal pain in the ass,
	// the design is overly complex for no good reason. But since we want to
	// be compatible, we have to imitate their behaviour.
	pwFileIdx := 0   // unless in display mode
	usernameIdx := 1 // this is the only one which is always there
	passwordIdx := 2 // only in batch mode

	nReqArgs := 2 // Normally, passwdFile and username are required.
	if *displayMode {
		// Display mode, no htpasswd file as argument.
		usernameIdx = 0
		passwordIdx = 1

		if !*batchMode {
			// When both -b and -n are specified, only a username is accepted.
			nReqArgs = 1
		}
	} else if *batchMode {
		// When only -b is specified, all three arguments are required.
		nReqArgs = 3
	}

	args := flag.Args()
	if len(args) != nReqArgs {
		usage(2)
	}
	// the hash
	hashFunc, ok := selectHashAlgorithmFromFlags()
	if !ok {
		usage(2)
	}

	var passwdFileName string
	if !*displayMode {
		passwdFileName = args[pwFileIdx]
		if *createOrTrunc {
			f, err := os.Create(args[pwFileIdx])
			if err != nil {
				fmt.Fprintf(os.Stderr, "htpasswd: cannot create file %s: %v\n", args[pwFileIdx], err)
				os.Exit(1)
			}
			f.Close()
		}
	}

	username := args[usernameIdx]
	if len(username) > 255 {
		fmt.Fprintln(os.Stderr, "htpasswd: username is too long")
		os.Exit(6)
	}
	if strings.ContainsRune(username, ':') {
		fmt.Fprintln(os.Stderr, "htpasswd: username contains illegal character ':'")
		os.Exit(6)
	}

	if *deleteUserFlag {
		err := deleteUser(passwdFileName, username)
		exit(err)
	}

	var password []byte
	if *batchMode {
		password = []byte(args[passwordIdx])
	} else {
		var err error
		password, err = readPassword()
		if err != nil {
			exit(err)
		}
	}

	if *verifyPasswordFlag {
		err := verifyPassword(passwdFileName, username, password)
		exit(err)
	}

	pwhash, err := hashFunc(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "htpasswd: %v\n", err)
		os.Exit(3)
	}

	if *displayMode {
		fmt.Printf("%s:%s\n", username, pwhash)
		os.Exit(0)
	}

	entries, err := readPasswdFile(passwdFileName)
	if err != nil {
		exit(err)
	}

	userFound := false
	for i := 0; i < len(entries); i++ {
		userStr := string(entries[i].user())
		if userStr == username {
			user := entries[i].user()
			entries[i] = newpwent(user, pwhash)
			userFound = true
		}
	}
	if !userFound {
		entries = append(entries, newpwent([]byte(username), pwhash))
	}
	if err := writeHtpasswdFile(passwdFileName, entries); err != nil {
		fmt.Fprintf(os.Stderr, "htpasswd: failed to write %s: %v", passwdFileName, err)
		os.Exit(1)
	}

	os.Exit(0)
}
