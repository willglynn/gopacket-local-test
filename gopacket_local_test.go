// gopacket_local_test uses pcap to capture on the first local interface, sets a
// filter, and sends a packet matching that filter, expecting it to be detected.
//
// By default, this test times out after 30 seconds. `go test --short` resets the
// timeout to 1 second after the packet is sent.
//
// By default, this test uses the first interface it finds on the machine. This
// is naïve, and the test will fail unless the selected interface is the one used
// to transmit packets to the Internet. You can override this as needed with
// `go test --interface eth1`.
package gopacket_local

import (
  "code.google.com/p/gopacket"
  _ "code.google.com/p/gopacket/layers"
  "code.google.com/p/gopacket/pcap"
  "flag"
  "net"
  "testing"
  "time"
)

var iface = flag.String("interface", "first", "interface to use for capturing")

func init() {
  flag.Parse()
}

// Send a UDP datagram to 8.8.8.8 (Google public DNS) on the discard port
func sendPacket(t *testing.T, done chan<- bool) {
  target, err := net.ResolveUDPAddr("udp4", "8.8.8.8:9")
  if err != nil {
    t.Fatal(err)
  }

  conn, err := net.DialUDP("udp4", nil, target)
  if err != nil {
    t.Fatal(err)
  }

  _, err = conn.Write([]byte("test packet, please ignore"))
  if err != nil {
    t.Fatal(err)
  }

  done <- true
}

func TestCapture(t *testing.T) {
  iface := *iface
  if iface == "first" {
    if ifs, err := pcap.FindAllDevs(); err != nil {
      t.Fatal(err)
    } else if len(ifs) > 0 {
      iface = ifs[0].Name
    } else {
      t.Fatal("no interface specified and none found")
    }
  }

  t.Logf("starting capture on interface %q", iface)

  handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
  if err != nil {
    t.Fatal(err)
  }
  // XXX: this causes a hang and/or segfault
  //defer handle.Close()

  if err := handle.SetBPFFilter("host 8.8.8.8 && port 9"); err != nil {
    t.Fatal(err)
  }

  t.Logf("capturing on %q", iface)

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  packets := packetSource.Packets()

  // send a detectable test packet in another goroutine
  packetSent := make(chan bool)
  go sendPacket(t, packetSent)

  timer := time.NewTimer(30 * time.Second)

  for {
    select {
    case packet := <-packets:
      t.Logf("captured packet: %+v", packet)

    case <-timer.C:
      t.Logf("%v: no packets received, timing out", time.Now())
      t.Fail()

    case <-packetSent:
      t.Logf("%v: packet sent", time.Now())
      if testing.Short() {
        timer.Reset(1 * time.Second)
      }

      continue
    }
    break
  }
}
