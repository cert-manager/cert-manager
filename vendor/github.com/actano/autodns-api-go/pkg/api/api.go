package api

import (
	"encoding/xml"
)

type Auth struct {
	User     string `xml:"user"`
	Password string `xml:"password"`
	Context  string `xml:"context"`
}

type Request struct {
	XMLName xml.Name `xml:"request"`
	Auth    Auth     `xml:"auth"`
}

type Task struct {
	Code string `xml:"code"`
}

type ResponseStatus struct {
	Type string `xml:"type"`
}

type Response struct {
	XMLName xml.Name       `xml:"response"`
	Status  ResponseStatus `xml:"result>status"`
}

func (r *Response) GetStatus() ResponseStatus {
	return r.Status
}

type Client interface {
	Auth() Auth
	MakeRequest(interface{}, ResponseWithStatus) error
}

func NewAuth(username, password, context string) Auth {
	return Auth{
		User:     username,
		Password: password,
		Context:  context,
	}
}

func NewRequest(auth Auth) Request {
	return Request{
		Auth: auth,
	}
}

func NewTask(code string) Task {
	return Task{
		Code: code,
	}
}

type ResponseWithStatus interface {
	GetStatus() ResponseStatus
}
