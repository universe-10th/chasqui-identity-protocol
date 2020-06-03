package main

import (
	"fmt"
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui/marshalers/json"
	. "github.com/universe-10th/chasqui/types"
	"net"
	"time"
)

type sampleClientFunnel struct {
	clientName string
	closer     func()
}

func (funnel sampleClientFunnel) Started(attendant *chasqui.Attendant) {
	fmt.Printf("Local(%s) starting\n", funnel.clientName)
}

func (funnel sampleClientFunnel) MessageArrived(attendant *chasqui.Attendant, message Message) {
	fmt.Printf("Local(%s) received: %v\n", funnel.clientName, message)
}

func (sampleClientFunnel) MessageThrottled(*chasqui.Attendant, Message, time.Time, time.Duration) {}

func (funnel sampleClientFunnel) Stopped(attendant *chasqui.Attendant, stopType chasqui.AttendantStopType, err error) {
	fmt.Printf("Local(%s) stopped: %d, %s\n", funnel.clientName, stopType, err)
	funnel.closer()
}

func makeClient(host, clientName string, onExtraClose func()) (*chasqui.Attendant, error) {
	if addr, err := net.ResolveTCPAddr("tcp", host); err != nil {
		return nil, err
	} else if conn, err := net.DialTCP("tcp", nil, addr); err != nil {
		return nil, err
	} else {
		client := chasqui.NewClient(conn, &json.JSONMessageMarshaler{}, 0, 16)
		chasqui.FunnelClientWith(client, sampleClientFunnel{clientName, onExtraClose})
		return client, nil
	}
}
