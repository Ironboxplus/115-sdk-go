// Command emu115 runs the 115 Open emulator as a standalone process so that
// OpenList cluster black-box tests can point storages at it.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/OpenListTeam/115-sdk-go/emu115"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	ttl := flag.Duration("ttl", 2*time.Hour, "access token lifetime")
	throttle := flag.Duration("throttle", 0, "40140117 window after a successful refresh")
	access := flag.String("access", "", "initial access token")
	refresh := flag.String("refresh", "", "initial refresh token")
	flag.Parse()

	srv := emu115.New(emu115.Config{AccessTTL: *ttl, RefreshThrottle: *throttle, AccessToken: *access, RefreshToken: *refresh})
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	a, r := srv.Tokens()
	// The tokens are throwaway emulator values, printed so a harness can seed storages.
	fmt.Printf("LISTEN %s\nACCESS %s\nREFRESH %s\n", ln.Addr(), a, r)
	log.Fatal(http.Serve(ln, srv.Handler()))
}
