package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	ethernetHeaderSize = 14
	sllHeaderSize      = 16
	sllHeaderSizeV2    = 20
)

// Predefined Ethernet header
var ethernetHeader = []byte{0x03, 0x7c, 0xec, 0x88, 0x0f, 0x02, 0x02, 0x9a, 0x54, 0x0b, 0xb6, 0x42, 0x08, 0x00}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	inputFileName, outputFileName, err := parseArgs()
	if err != nil {
		return fmt.Errorf("error parsing arguments: %w", err)
	}

	handle, err := pcap.OpenOffline(inputFileName)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %w", err)
	}
	defer handle.Close()

	writer, outputFile, err := createPcapWriter(outputFileName)
	if err != nil {
		return fmt.Errorf("error creating pcap writer: %w", err)
	}
	defer outputFile.Close()

	if err := processPackets(handle, writer); err != nil {
		return fmt.Errorf("error processing packets: %w", err)
	}

	fmt.Println("PCAP processing complete. Modified packets saved to output file.")
	return nil
}

func parseArgs() (string, string, error) {
	if len(os.Args) != 3 {
		return "", "", fmt.Errorf("usage: %s <input.pcap> <output.pcap>", os.Args[0])
	}
	return os.Args[1], os.Args[2], nil
}

func createPcapWriter(outputFileName string) (*pcapgo.Writer, *os.File, error) {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating output pcap file: %w", err)
	}

	writer := pcapgo.NewWriter(outputFile)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		outputFile.Close()
		return nil, nil, fmt.Errorf("error writing file header: %w", err)
	}

	return writer, outputFile, nil
}

func processPackets(handle *pcap.Handle, writer *pcapgo.Writer) error {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		newData, err := modifyPacket(packet.Data())
		if err != nil {
			return fmt.Errorf("error modifying packet: %w", err)
		}

		if err := writePacket(writer, packet.Metadata().Timestamp, newData); err != nil {
			return fmt.Errorf("error writing packet to output: %w", err)
		}
	}

	return nil
}

func writePacket(writer *pcapgo.Writer, timestamp time.Time, data []byte) error {
	return writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(data),
		Length:         len(data),
		InterfaceIndex: 0,
	}, data)
}

func modifyPacket(data []byte) ([]byte, error) {
	if len(data) < sllHeaderSize {
		return data, nil // Packet too short, return unmodified
	}

	// Check the packet type in the SLL header
	packetType := binary.BigEndian.Uint16(data[:2])

	headerSize := sllHeaderSize
	if packetType > 4 {
		// Possibly SLL2 or other variants
		headerSize = sllHeaderSizeV2
	}

	if len(data) < headerSize+ethernetHeaderSize {
		return data, nil // Packet too short for modification, return unmodified
	}

	// Create a new slice with the capacity to hold the entire modified packet
	newData := make([]byte, 0, len(ethernetHeader)+len(data)-headerSize)
	newData = append(newData, ethernetHeader...)
	newData = append(newData, data[headerSize:]...)

	return newData, nil
}
