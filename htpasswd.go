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
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type hashfunc func(string) (string, error)
type comparefunc func(string, string) error

type algorithm struct {
	enabled  bool
	hashFunc hashfunc
}

type pwent struct {
	user   string
	pwhash string
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
var crypt64Encoding = base64.NewEncoding(crypt64Alphabet)
var errVerificationFailed = fmt.Errorf("password verification error")

func (e *formatError) Error() string {
	return fmt.Sprintf("The file %s does not appear to be a valid htpasswd file.", e.filename)
}

func (e *userError) Error() string {
	return fmt.Sprintf("User %s not found\n", e.username)
}

func seed() {
	if !randSeeded {
		rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
	}
}

func b64Encode(hash []byte, encoding *base64.Encoding) string {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(encoding, &buf)
	encoder.Write(hash)
	encoder.Close()
	return buf.String()
}

func md5Impl(pw, salt string) (string, error) {
	// TODO: this is default md5, but htpasswd uses a modified variant
	res := md5.Sum([]byte(salt + pw))
	return fmt.Sprintf("$apr1$%s$%s", salt, b64Encode(res[:], crypt64Encoding)), nil
}

func md5Func(pw string) (string, error) {
	seed()
	saltb := [6]byte{}
	rand.Read(saltb[:])
	salt := b64Encode(saltb[:], crypt64Encoding)
	fmt.Fprintf(os.Stderr, "salt encoded length: %d\n", len(salt))
	return md5Impl(pw, salt[:8])
}

func md5Compare(pw, hash string) error {
	salt := strings.Split(hash, "$")[2]
	pwhash, err := md5Impl(pw, salt)
	if err == nil && hash != pwhash {
		err = errVerificationFailed
	}
	return err
}

func bcryptFunc(pw string) (string, error) {
	cost := *bcryptCost
	if cost < 4 || cost > 17 {
		return "", fmt.Errorf("Unable to encode with bcrypt: Invalid argument")
	}
	res, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %v", err)
	}
	return fmt.Sprintf("$%s$%02d$%s", "2y", cost, string(res)), nil
}

func bcryptCompare(pw, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
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

func crypt3Func(pw string) (string, error) {
	if len(pw) > 8 {
		pw = pw[:8]
	}
	blk, err := des.NewCipher([]byte(pw))
	if err != nil {
		return "", err
	}
	data := make([]byte, blk.BlockSize())
	blk.Encrypt(data, data)
	return b64Encode(data, crypt64Encoding), nil
}

func crypt3Compare(pw, hash string) error {
	pwhash, err := crypt3Func(pw)
	if err == nil && hash != pwhash {
		err = errVerificationFailed
	}
	return err
}

func shaFunc(pw string) (string, error) {
	res := sha1.Sum([]byte(pw))
	return "{SHA}" + b64Encode(res[:], base64.StdEncoding), nil
}

func shaCompare(pw, hash string) error {
	pwhash, err := shaFunc(pw)
	if err == nil && hash != pwhash {
		err = errVerificationFailed
	}
	return err
}

func plainFunc(pw string) (string, error) {
	return pw, nil
}

func plainCompare(pw, other string) error {
	if pw == other {
		return nil
	}
	return errVerificationFailed
}

func selectHashAlgorithmFromFlags() (hashfunc, bool) {
	allFlags := []algorithm{
		algorithm{*hashMd5, md5Func},
		algorithm{*hashBcrypt, bcryptFunc},
		algorithm{*hashCrypt3, crypt3Func},
		algorithm{*hashSha, shaFunc},
		algorithm{*hashPlain, plainFunc},
	}
	var hf hashfunc = nil
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
		hf = md5Func
	}
	return hf, true
}

func readLine(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		err := scanner.Err()
		if err != nil {
			return "", err
		}
		os.Exit(4) // count this as interrupted for now
	}
	return scanner.Text(), nil
}

func readPassword() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if *scriptMode {
		return readLine(scanner)
	}
	if *verifyPasswordFlag {
		fmt.Printf("Enter password:")
		// TODO: echo off
		return readLine(scanner)
	}
	fmt.Printf("New password:")
	// TODO: echo off
	pw, err := readLine(scanner)
	if err != nil {
		return "", err
	}
	fmt.Printf("Re-type new password:")
	// TODO: echo off
	pw2, err := readLine(scanner)
	if err != nil {
		return "", err
	}
	if pw != pw2 {
		return "", errVerificationFailed
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
	entries := []pwent{}
	for scanner.Scan() {
		pwline := strings.SplitN(scanner.Text(), ":", 2)
		if len(pwline) != 2 {
			return nil, &formatError{filename}
		}
		entries = append(entries, pwent{pwline[0], pwline[1]})
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
		if _, err := fmt.Fprintf(&buf, "%s:%s\n", e.user, e.pwhash); err != nil {
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
		if e.user == username {
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

func verifyPassword(filename, username, password string) error {
	entries, err := readPasswdFile(filename)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.user == username {
			var cf comparefunc
			switch e.pwhash[0] {
			case '$':
				l := strings.Split(e.pwhash, "$")
				// "$apr1$salt$hash" splits to []string{"", "apr1", "salt", "hash"}
				if len(l) != 4 {
					return &formatError{filename}
				}
				switch l[1] {
				case "apr1":
					cf = md5Compare
				case "2y":
					cf = bcryptCompare
				default:
					return &formatError{filename}
				}
			case '{':
				cf = shaCompare
			default:
				// Plain-text passwords and DES digests look virtually the
				// same, so just check for the plain-text password first and
				// it is not a match, try the crypt(3) function.
				cf = func(pw, hash string) error {
					err := plainCompare(pw, hash)
					if err != nil {
						err = crypt3Compare(pw, hash)
					}
					return err
				}
			}
			err := cf(password, e.pwhash)
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
	if strings.Contains(username, ":") {
		fmt.Fprintln(os.Stderr, "htpasswd: username contains illegal character ':'")
		os.Exit(6)
	}

	if *deleteUserFlag {
		err := deleteUser(passwdFileName, username)
		exit(err)
	}

	password := ""
	if *batchMode {
		password = args[passwordIdx]
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
		if entries[i].user == username {
			entries[i].pwhash = pwhash
			userFound = true
		}
	}
	if !userFound {
		entries = append(entries, pwent{username, pwhash})
	}
	if err := writeHtpasswdFile(passwdFileName, entries); err != nil {
		fmt.Fprintf(os.Stderr, "htpasswd: failed to write %s: %v", passwdFileName, err)
		os.Exit(1)
	}

	os.Exit(0)
}
