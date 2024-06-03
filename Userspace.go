package main

import (
    "encoding/binary"
    "fmt"
    "os"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/vishvananda/netlink"
)

const (
    mapKey      = 0
    defaultPort = 4040
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <interface>\n", os.Args[0])
        os.Exit(1)
    }
    iface := os.Args[1]

    port := defaultPort
    if len(os.Args) > 2 {
        p, err := strconv.Atoi(os.Args[2])
        if err != nil {
            fmt.Printf("Invalid port: %v\n", err)
            os.Exit(1)
        }
        port = p
    }

    spec, err := ebpf.LoadCollectionSpec("xdp_prog_drop.o")
    if err != nil {
        fmt.Printf("Error loading eBPF program: %v\n", err)
        os.Exit(1)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        fmt.Printf("Error creating eBPF collection: %v\n", err)
        os.Exit(1)
    }
    defer coll.Close()

    dropPortMap := coll.Maps["drop_port_map"]
    if dropPortMap == nil {
        fmt.Printf("Error finding map: drop_port_map\n")
        os.Exit(1)
    }

    portBytes := make([]byte, 2)
    binary.LittleEndian.PutUint16(portBytes, uint16(port))
    if err := dropPortMap.Update(unsafe.Pointer(&mapKey), unsafe.Pointer(&portBytes[0]), ebpf.UpdateAny); err != nil {
        fmt.Printf("Error updating map: %v\n", err)
        os.Exit(1)
    }

    link, err := link.AttachXDP(link.XDPOptions{
        Program:   coll.Programs["xdp_prog_drop"],
        Interface: iface,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        fmt.Printf("Error attaching XDP program: %v\n", err)
        os.Exit(1)
    }
    defer link.Close()

    fmt.Printf("eBPF program loaded and attached to interface %s on port %d\n", iface, port)
    select {}
}
