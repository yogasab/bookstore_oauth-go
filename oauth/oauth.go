package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/yogasab/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-ID"
	headerXCallerID = "X-Caller-ID"

	paramAccessTokenID = "access_token"
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) *errors.ResponseError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessTokenID))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Code == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Set(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Set(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}

	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}

	return clientID
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.ResponseError) {
	response, _ := resty.New().R().Get(fmt.Sprintf("http://localhost:5000/api/v1/oauth/access-token/%s", accessTokenID))
	if response == nil || response.RawResponse == nil {
		return nil, errors.FormatError(http.StatusInternalServerError, "failed", "invalid restclient response when trying to get access token")
	}

	if response.StatusCode() > 299 {
		var errResp errors.ResponseError
		err := json.Unmarshal(response.Body(), &errResp)
		if err != nil {
			return nil, errors.FormatError(http.StatusInternalServerError, "failed", "invalid error interface when trying to get access token")
		}
		return nil, &errResp
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, errors.FormatError(http.StatusInternalServerError, "failed", "error when trying to unmarshal access token response")
	}

	return &at, nil
}
