package main

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-identity-protocols/auth"
	realms2 "github.com/universe-10th/chasqui-identity-protocols/auth/samples/realms"
	protocols "github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/marshalers/json"
	"github.com/universe-10th/identity/realms"
)

var funnel, _ = protocols.NewProtocolsFunnel([]protocols.Protocol{NewChatProtocol(auth.NewAuthProtocol(
	map[string]*realms.Realm{
		"main": realms2.DummyRealm,
	}, auth.WithPrefix("my-auth"),
))})

func makeServer() *chasqui.Server {
	return chasqui.NewServer(
		&json.JSONMessageMarshaler{}, 1024, 1, 0,
	)
}

func funnelServer(server *chasqui.Server) {
	chasqui.FunnelServerWith(server, funnel)
}
