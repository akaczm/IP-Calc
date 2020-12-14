// Primitive exercise in structures using IPv4 as an example

package main

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// IPv4 holds the address and netmask in uint32 format
type IPv4 struct {
	addr uint32
	mask uint32
}

// NewIP generates a new IP based on a string using CIDR notation (eg. 10.0.0.1/24).
func NewIP(address string) (IPv4, error) {
	split := strings.Split(address, "/")
	addr := split[0]
	ipv4, err := decodeAddress(addr)
	if err != nil {
		return IPv4{}, errors.Wrap(err, "Error creating IPv4")
	}
	mask := split[1]
	bitmask, err := decodeMask(mask)
	if err != nil {
		return IPv4{}, errors.Wrap(err, "Error creating IPv4")
	}
	ip := IPv4{ipv4, bitmask}
	return ip, nil
}

// ToString returns the IPv4 struct as a string in CIDR notation.
func (ip IPv4) ToString() string {
	ipstring := stringFormatIP(ip.addr)
	maskbits := bits.OnesCount32(ip.mask)
	output := fmt.Sprintf("%v/%v", ipstring, maskbits)
	return output
}

func stringFormatIP(address uint32) string {
	bitmask := uint32(0b11111111)
	octets := make([]uint32, 0)
	for i := 0; i < 4; i++ {
		octet := address & bitmask
		octets = append(octets, octet)
		address = address >> 8
	}
	output := fmt.Sprintf("%v.%v.%v.%v", octets[3], octets[2], octets[1], octets[0])
	return output
}

// GetNetworkAddress obtains the network address of a subnet and returns it as string.
func (ip IPv4) GetNetworkAddress() string {
	netaddr := ip.mask & ip.addr
	netaddrString := stringFormatIP(netaddr)
	return netaddrString
}

// GetBroadcastAddress obtains the network address of a subnet and returns it as string.
func (ip IPv4) GetBroadcastAddress() string {
	bcastaddr := ip.addr | ^ip.mask
	bcastaddrString := stringFormatIP(bcastaddr)
	return bcastaddrString
}

// GetHostAddressRange obtains addresses available for a host and returns it as two string values (min max).
func (ip IPv4) GetHostAddressRange() (string, string) {
	maskbits := bits.OnesCount32(ip.mask)
	if maskbits == 32 {
		return ip.GetNetworkAddress(), ""
	}
	if maskbits == 31 {
		return ip.GetNetworkAddress(), ip.GetBroadcastAddress()
	}
	hostmin := ip.mask&ip.addr + 1
	hostmax := ip.addr | ^ip.mask - 1
	return stringFormatIP(hostmin), stringFormatIP(hostmax)
}

// decodeAddress decodes IPv4 address and converts it into proper uint32 values
func decodeAddress(address string) (uint32, error) {
	split := strings.Split(address, ".")
	if len(split) != 4 {
		return 0, errors.New("Error decoding IPv4 address: wrong amount of octets")
	}
	var IPaddress uint32
	for i, octetstr := range split {
		segment, err := strconv.Atoi(octetstr)
		if err != nil {
			return 0, errors.Wrap(err, "Error decoding IPv4 address")
		}
		if segment > math.MaxUint8 {
			return 0, errors.New("Error decoding IPv4 address: value overflow")
		}
		// Shift octets by determined amount of bits.
		switch i {
		case 0:
			segment = segment << 24
		case 1:
			segment = segment << 16
		case 2:
			segment = segment << 8
		}
		IPaddress += uint32(segment)
	}
	return IPaddress, nil
}

// decodeMask decodes the netmask and does simple validation.
func decodeMask(mask string) (uint32, error) {
	imask, err := strconv.Atoi(mask)
	imask = 32 - imask
	outmask := uint32(0b11111111111111111111111111111111)
	if err != nil {
		return 0, errors.Wrap(err, "Error decoding netmask")
	}
	if imask > 32 || imask < 0 {
		return 0, errors.New("Mask out of bounds")
	}
	for i := 0; i < imask; i++ {
		outmask -= 1 << i
	}
	return outmask, nil
}

func main() {
	args := os.Args[1:]

	if len(os.Args) < 2 {
		fmt.Println("Usage - ipcalc n.n.n.n/n")
		fmt.Println("Only CIDR notation accepted")
		os.Exit(0)
	}

	for _, arg := range args {
		ip, err := NewIP(arg)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\n")
		fmt.Printf("IP Addr:     %s\n", ip.ToString())
		fmt.Printf("Net Address: %s\n", ip.GetNetworkAddress())
		fmt.Printf("Broadcast:   %s\n", ip.GetBroadcastAddress())
		hostmin, hostmax := ip.GetHostAddressRange()
		fmt.Printf("Host range:  %s - %s\n", hostmin, hostmax)
	}
}
