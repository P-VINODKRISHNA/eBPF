package main

import (
    "encoding/binary"
    "fmt"
    "os"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

const (
    processName = "myprocess"
    defaultPort = 4040
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <interface>\n", os.Args[0])
        os.Exit(1)
    }
    iface := os.Args[1]

    port := defaultPort

    spec, err := ebpf.LoadCollectionSpec("xdp_prog.o")
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

    configMap := coll.Maps["config_map"]
    if configMap == nil {
        fmt.Printf("Error finding map: config_map\n")
        os.Exit(1)
    }

    portBytes := make([]byte, 2)
    binary.LittleEndian.PutUint16(portBytes, uint16(port))
    processKey := make([]byte, 16)
    copy(processKey, processName)

    if err := configMap.Update(unsafe.Pointer(&processKey[0]), unsafe.Pointer(&portBytes[0]), ebpf.UpdateAny); err != nil {
        fmt.Printf("Error updating map: %v\n", err)
        os.Exit(1)
    }

    link, err := link.AttachXDP(link.XDPOptions{
        Program:   coll.Programs["xdp_prog_func"],
        Interface: iface,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        fmt.Printf("Error attaching XDP program: %v\n", err)
        os.Exit(1)
    }
    defer link.Close()

    fmt.Printf("eBPF program loaded and attached to interface %s\n", iface)
    select {}
}
