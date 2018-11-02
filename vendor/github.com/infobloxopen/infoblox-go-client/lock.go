package ibclient

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"math/rand"
	"time"
)

const (
	timeout     int32  = 60 // in seconds
	freeLockVal string = "Available"
)

type Lock interface {
	Lock() error
	UnLock(force bool) error
}

type NetworkViewLock struct {
	Name          string
	ObjMgr        *ObjectManager
	LockEA        string
	LockTimeoutEA string
}

func (l *NetworkViewLock) createLockRequest() *MultiRequest {

	req := NewMultiRequest(
		[]*RequestBody{
			&RequestBody{
				Method: "GET",
				Object: "networkview",
				Data: map[string]interface{}{
					"name":         l.Name,
					"*" + l.LockEA: freeLockVal,
				},
				Args: map[string]string{
					"_return_fields": "extattrs",
				},
				AssignState: map[string]string{
					"NET_VIEW_REF": "_ref",
				},
				Discard: true,
			},
			&RequestBody{
				Method: "PUT",
				Object: "##STATE:NET_VIEW_REF:##",
				Data: map[string]interface{}{
					"extattrs+": map[string]interface{}{
						l.LockEA: map[string]string{
							"value": l.ObjMgr.tenantID,
						},
						l.LockTimeoutEA: map[string]int32{
							"value": int32(time.Now().Unix()),
						},
					},
				},
				EnableSubstitution: true,
				Discard:            true,
			},
			&RequestBody{
				Method: "GET",
				Object: "##STATE:NET_VIEW_REF:##",
				Args: map[string]string{
					"_return_fields": "extattrs",
				},
				AssignState: map[string]string{
					"DOCKER-ID": "*" + l.LockEA,
				},
				EnableSubstitution: true,
				Discard:            true,
			},
			&RequestBody{
				Method: "STATE:DISPLAY",
			},
		},
	)

	return req
}

func (l *NetworkViewLock) createUnlockRequest(force bool) *MultiRequest {

	getData := map[string]interface{}{"name": l.Name}
	if !force {
		getData["*"+l.LockEA] = l.ObjMgr.tenantID
	}

	req := NewMultiRequest(
		[]*RequestBody{
			&RequestBody{
				Method: "GET",
				Object: "networkview",
				Data:   getData,
				Args: map[string]string{
					"_return_fields": "extattrs",
				},
				AssignState: map[string]string{
					"NET_VIEW_REF": "_ref",
				},
				Discard: true,
			},
			&RequestBody{
				Method: "PUT",
				Object: "##STATE:NET_VIEW_REF:##",
				Data: map[string]interface{}{
					"extattrs+": map[string]interface{}{
						l.LockEA: map[string]string{
							"value": freeLockVal,
						},
					},
				},
				EnableSubstitution: true,
				Discard:            true,
			},
			&RequestBody{
				Method: "PUT",
				Object: "##STATE:NET_VIEW_REF:##",
				Data: map[string]interface{}{
					"extattrs-": map[string]interface{}{
						l.LockTimeoutEA: map[string]interface{}{},
					},
				},
				EnableSubstitution: true,
				Discard:            true,
			},
			&RequestBody{
				Method: "GET",
				Object: "##STATE:NET_VIEW_REF:##",
				Args: map[string]string{
					"_return_fields": "extattrs",
				},
				AssignState: map[string]string{
					"DOCKER-ID": "*" + l.LockEA,
				},
				EnableSubstitution: true,
				Discard:            true,
			},
			&RequestBody{
				Method: "STATE:DISPLAY",
			},
		},
	)

	return req
}

func (l *NetworkViewLock) getLock() bool {
	logrus.Debugf("Creating lock on network niew %s\n", l.Name)
	req := l.createLockRequest()
	res, err := l.ObjMgr.CreateMultiObject(req)

	if err != nil {
		logrus.Debugf("Failed to create lock on network view %s: %s\n", l.Name, err)

		//Check for Lock Timeout
		nw, err := l.ObjMgr.GetNetworkView(l.Name)
		if err != nil {
			logrus.Debugf("Failed to get the network view object for %s : %s\n", l.Name, err)
			return false
		}

		if t, ok := nw.Ea[l.LockTimeoutEA]; ok {
			if int32(time.Now().Unix())-int32(t.(int)) > timeout {
				logrus.Debugln("Lock is timed out. Forcefully acquiring it.")
				//remove the lock forcefully and acquire it
				l.UnLock(true)
				// try to get lock again
				return l.getLock()
			}
		}
		return false
	}

	dockerID := res[0]["DOCKER-ID"]
	if dockerID == l.ObjMgr.tenantID {
		logrus.Debugln("Got the lock !!!")
		return true
	}

	return false
}

func (l *NetworkViewLock) Lock() error {

	// verify if network view exists and has EA for the lock
	nw, err := l.ObjMgr.GetNetworkView(l.Name)
	if err != nil {
		msg := fmt.Sprintf("Failed to get the network view object for %s : %s\n", l.Name, err)
		logrus.Debugf(msg)
		return fmt.Errorf(msg)
	}

	if _, ok := nw.Ea[l.LockEA]; !ok {
		err = l.ObjMgr.UpdateNetworkViewEA(nw.Ref, EA{l.LockEA: freeLockVal}, nil)
		if err != nil {
			return fmt.Errorf("Failed to Update Network view with Lock EA")
		}
	}

	retryCount := 0
	for {
		// Get lock on the network view
		lock := l.getLock()
		if lock == true {
			// Got the lock.
			logrus.Debugf("Got the lock on Network View %s\n", l.Name)
			return nil
		}

		// Lock is held by some other agent. Wait for some time and retry it again
		if retryCount >= 10 {
			return fmt.Errorf("Failed to get Lock on Network View %s", l.Name)
		}

		retryCount++
		logrus.Debugf("Lock on Network View %s not free. Retrying again %d out of 10.\n", l.Name, retryCount)
		// sleep for random time (between 1 - 10 seconds) to reduce collisions
		time.Sleep(time.Duration(rand.Intn(9)+1) * time.Second)
		continue
	}
}

func (l *NetworkViewLock) UnLock(force bool) error {
	// To unlock set the Docker-Plugin-Lock EA of network view to Available and
	// remove the Docker-Plugin-Lock-Time EA
	req := l.createUnlockRequest(force)
	res, err := l.ObjMgr.CreateMultiObject(req)

	if err != nil {
		msg := fmt.Sprintf("Failed to release lock from Network View %s: %s\n", l.Name, err)
		logrus.Errorf(msg)
		return fmt.Errorf(msg)
	}

	dockerID := res[0]["DOCKER-ID"]
	if dockerID == freeLockVal {
		logrus.Debugln("Removed the lock!")
		return nil
	}

	msg := fmt.Sprintf("Failed to release lock from Network View %s\n", l.Name)
	logrus.Errorf(msg)
	return fmt.Errorf(msg)
}
