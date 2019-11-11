package pass

import (
	"strings"
	"testing"

	"github.com/docker/docker-credential-helpers/credentials"
)

func TestPassHelper(t *testing.T) {
	helper := Pass{}

	creds := &credentials.Credentials{
		ServerURL: "https://foobar.docker.io:2376/v1",
		Username:  "nothing",
		Secret:    "isthebestmeshuggahalbum",
	}

	helper.Add(creds)

	creds.ServerURL = "https://foobar.docker.io:9999/v2"
	helper.Add(creds)

	credsList, err := helper.List()
	if err != nil {
		t.Fatal(err)
	}

	for server, username := range credsList {
		if !(strings.Contains(server, "2376") ||
			strings.Contains(server, "9999")) {
			t.Fatalf("invalid url: %s", creds.ServerURL)
		}

		if username != "nothing" {
			t.Fatalf("invalid username: %v", username)
		}

		u, s, err := helper.Get(server)
		if err != nil {
			t.Fatal(err)
		}

		if u != username {
			t.Fatalf("invalid username %s", u)
		}

		if s != "isthebestmeshuggahalbum" {
			t.Fatalf("invalid secret: %s", s)
		}

		err = helper.Delete(server)
		if err != nil {
			t.Fatal(err)
		}

		username, _, err = helper.Get(server)
		if err != nil {
			t.Fatal(err)
		}

		if username != "" {
			t.Fatalf("%s shouldn't exist any more", username)
		}
	}

	credsList, err = helper.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(credsList) != 0 {
		t.Fatal("didn't delete all creds?")
	}
}

const maxFileNameLength = 120 // encrypted ext4 max 143, keep it bellow 128 and have reserve for suffix

func encodePath(serverURL, username) string {
	// separate serverURL and username
	serverAndUsername = strings.Join(
		[]string{strings.TrimSuffix(serverURL, username), username}, "\x00",
	)
	// encode base64
	encoded := base64.URLEncoding.EncodeToString([]byte(serverAndUsername))
	// split if folder name too long
	splited := []string{}
	part := ""
	for i, r := range encoded {
		if i%maxFileNameLength == 0 && i != 0 && len(encoded) {
			splited = append(splited, part)
			part = ""
		}
		part += r
	}
	if len(part) != 0 {
		splited = append(splited, part)
	}
	// add data file
	splited = append(splited, "data.gpg")
	return filepath.Join(splited)
}

func decodePath(path string) (serverURL, username string, err error) {
	// split folders and check encoded path
	splited := filepath.Split(path)
	if len(splited) < 2 || splited[len(splited)] != "data.gpg" {
		return "", "", errors.New("incorrect path encoding: no data.gpg")
	}
	// join and decode
	decoded, err := base64.URLEncoding.DecodeString(
		strings.Join(splited[:len(splited)-1], ""),
	)
	if err != nil {
		return "", "", errors.Wrap(err, "incorrect path encoding")
	}
	// separate and check serverURL and username
	serverAndUsername := strings.Split(decoded, "\x00")
	if len(serverAndUsername) != 2 {
		return "", "", errors.New("incorrect path encoding: no delimiter")
	}

	username = serverAndUsername[1]
	serverURL = serverAndUsername[0] + username

	return
}

func TestEncodeDecodePath(t *testing.T) {
	username := "jMzPG9_Vi8jxr6GqkLm05igLcX04kR5Jq15A_safAM49vTqtoWn8CLhiQR9uOwHxpnwLDtCDGYIaq8Y2QfiMeQ=="
	serverURL := "protonmail/bridge/users/" + username
	expPath := "cHJvdG9ubWFpbC9icmlkZ2UvdXNlcnMvAGpNelBHOV9WaThqeHI2R3FrTG0wNWlnTGNYMDRrUjVKcTE1QV9zYWZBTTQ5dlRxdG9XbjhDTGhpUVI5dU93SHhw/bndMRHRDREdZSWFxOFkyUWZpTWVRPT0=/data.gpg"

	// separate server and username
	path := encodePath(serverURL, username)
	if expPath != path {
		t.Failf(" expected path %q but got %q", expPath, path)
	}

	decURL, decUsername, err = decodePath(expPath)
	if err != nil {
		t.Failf("error while decodePath: %v", err)
	}
	if decURL != serverURL {
		t.Failf(" expected URL %q but got %q", serverURL, decURL)
	}
	if decUsername != username {
		t.Failf(" expected username %q but got %q", decUsername, username)
	}
}
