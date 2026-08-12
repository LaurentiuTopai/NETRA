package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"edr-agent/pkg/detector"
	"edr-agent/pkg/events"
	"edr-agent/pkg/rootkit"
	"edr-agent/pkg/store"
)

// Directive bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type filer_event filer ../../../kernel/filer.bpf.c -- -I../../../kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type exit_event edr ../../../kernel/edr.bpf.c -- -I../../../kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type network_event network ../../../kernel/network.bpf.c -- -I../../../kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type rootkit_event rootkit ../../../kernel/rootkit.bpf.c -- -I../../../kernel

func Start(ctx context.Context) error {
	//1.Permisiuni pentru memorie
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Erroare memlock: %v\n", err)
	}

	//2.InitializareStocare
	procStore := store.NewProcessStore()
	ransomwareDet := detector.NewRansomewareDetector(procStore, ctx)
	spywareDet := detector.NewSpywareDetector(procStore, ctx)
	hardwareDet := detector.NewHardwareBlockDetector(true, true, true, ctx)
	rootkitDet := rootkit.NewRootkit(procStore, ctx)

	//3.Incarcare eBPF
	var edrObjs edrObjects
	if err := loadEdrObjects(&edrObjs, nil); err != nil {
		log.Fatalf("Erroare incarcare EDR eBPF: %v\n", err)
	}
	defer edrObjs.Close()

	var filerObjs filerObjects
	if err := loadFilerObjects(&filerObjs, nil); err != nil {
		log.Fatalf("Erroare incarcare Filer eBPF: %v\n", err)
	}
	defer filerObjs.Close()

	var networkObjs networkObjects
	if err := loadNetworkObjects(&networkObjs, nil); err != nil {
		log.Fatalf("Erroare incarcare Network eBPF: %v\n", err)
	}
	defer networkObjs.Close()

	var rootkitObjs rootkitObjects
	if err := loadRootkitObjects(&rootkitObjs, nil); err != nil {
		log.Fatalf("Erroare incarcare Rootkit eBPF: %v\n", err)
	}
	defer rootkitObjs.Close()

	//Atasare programe EDR (Tracepoints)
	tpExecve, err := link.Tracepoint("syscalls", "sys_exit_execve", edrObjs.HandleExecveExit, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_exit_execve: %v\n", err)
	}
	defer tpExecve.Close()

	tpProcExit, err := link.Tracepoint("sched", "sched_process_exit", edrObjs.HandleProcessExit, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sched_process_exit: %v\n", err)
	}
	defer tpProcExit.Close()

	//Atasare programe Filer (Tracepoints)
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", filerObjs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_openat: %v\n", err)
	}
	defer tpOpenat.Close()

	// --- Ataşare programe Network (Tracepoints) ---
	kpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", networkObjs.HandleConnect, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_connect: %v", err)
	}
	defer kpConnect.Close()

	kpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", networkObjs.HandleSendto, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_sendto: %v", err)
	}
	defer kpSendto.Close()

	kpSocket, err := link.Tracepoint("syscalls", "sys_enter_socket", networkObjs.HandleSocket, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_socket: %v", err)
	}
	defer kpSocket.Close()

	// --- Ataşare programe Rootkit (Tracepoints) ---
	tpMemfd, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", rootkitObjs.HandleMemfdCreate, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_memfd_create: %v", err)
	}
	defer tpMemfd.Close()

	tpFinitModule, err := link.Tracepoint("syscalls", "sys_enter_finit_module", rootkitObjs.HandleFinitModule, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_finit_module: %v", err)
	}
	defer tpFinitModule.Close()

	tpPtrace, err := link.Tracepoint("syscalls", "sys_enter_ptrace", rootkitObjs.HandlePtrace, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_ptrace: %v", err)
	}
	defer tpPtrace.Close()

	tpBpf, err := link.Tracepoint("syscalls", "sys_enter_bpf", rootkitObjs.HandleBpf, nil)
	if err != nil {
		log.Fatalf("Eroare atașare tracepoint sys_enter_bpf: %v", err)
	}
	defer tpBpf.Close()

	// Ring Buffers
	rbFiler, err := ringbuf.NewReader(filerObjs.Rb)
	if err != nil {
		log.Fatalf("Erroare deschidere Filer RingBuffer: %v", err)
	}
	defer rbFiler.Close()

	rbNetwork, err := ringbuf.NewReader(networkObjs.Rb)
	if err != nil {
		log.Fatalf("Erroare deschidere Network RingBuffer: %v", err)
	}
	defer rbNetwork.Close()

	rbEdrExit, err := ringbuf.NewReader(edrObjs.ExitRb)
	if err != nil {
		log.Fatalf("Erroare deschidere Exit RingBuffer: %v", err)
	}
	defer rbEdrExit.Close()

	rbRootkit, err := ringbuf.NewReader(rootkitObjs.Rb)
	if err != nil {
		log.Fatalf("Erroare deschidere Rootkit RingBuffer: %v", err)
	}
	defer rbRootkit.Close()

	go func() {
		var event filerFilerEvent
		for {
			record, err := rbFiler.Read()
			if err != nil {
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			comm := int8ToString(event.Comm[:])
			filename := int8ToString(event.Filename[:])

			isWrite := (event.Flags&unix.O_ACCMODE) == unix.O_WRONLY || (event.Flags&unix.O_ACCMODE) == unix.O_RDWR
			isRead := (event.Flags&unix.O_ACCMODE) == unix.O_RDONLY || (event.Flags&unix.O_ACCMODE) == unix.O_RDWR

			if isWrite {
				ransomwareDet.OnFileWrite(event.Pid, comm, filename)
			}
			if isRead {
				spywareDet.OnSensitiveRead(event.Pid, comm, filename)
				hardwareDet.OnDeviceOpen(event.Pid, comm, filename)
			}
		}
	}()

	go func() {
		var event networkNetworkEvent
		packetSeq := 0
		for {
			record, err := rbNetwork.Read()
			if err != nil {
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			comm := int8ToString(event.Comm[:])
			ipStr := parseIp(event.Family, event.Ip4, event.Ip6)
			spywareDet.OnNetworkConnect(event.Pid, comm, ipStr, event.Port)

			// Filtram traficul local (loopback 127.x.x.x / ::1 / 0.0.0.0) pentru Traffic Tracker
			if isLocalIP(ipStr) {
				continue
			}

			packetSeq++
			protoStr := "TCP"
			switch event.Protocol {
			case 1:
				protoStr = "TCP"
			case 2:
				protoStr = "UDP"
			case 3:
				protoStr = "DNS"
			case 4:
				protoStr = "ICMP"
			}

			payloadBytes := make([]byte, 0, event.Len)
			for i := uint32(0); i < event.Len && i < uint32(len(event.Data)); i++ {
				payloadBytes = append(payloadBytes, byte(event.Data[i]))
			}

			payloadStr := string(payloadBytes)
			hexDumpStr := formatHexDump(payloadBytes)

			events.SendNetworkPacket(ctx, events.NetworkPacket{
				ID:        packetSeq,
				Timestamp: time.Now().Format("15:04:05.000"),
				Pid:       event.Pid,
				Comm:      comm,
				Protocol:  protoStr,
				SrcIP:     "192.168.1.100",
				DstIP:     ipStr,
				DstPort:   event.Port,
				Len:       event.Len,
				Payload:   payloadStr,
				HexDump:   hexDumpStr,
			})
		}
	}()

	go func() {
		var event edrExitEvent
		for {
			record, err := rbEdrExit.Read()
			if err != nil {
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			procStore.Remove(event.Pid)
		}
	}()

	go func() {
		var event rootkitRootkitEvent
		for {
			record, err := rbRootkit.Read()
			if err != nil {
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			rootkitDet.TrackEvent(rootkit.Event{
				Type:   event.Type,
				Pid:    event.Pid,
				Ppid:   event.Ppid,
				Uid:    event.Uid,
				Comm:   int8ToString(event.Comm[:]),
				Arg1:   event.Arg1,
				Arg2:   event.Arg2,
				StrArg: int8ToString(event.StrArg[:]),
			})
		}
	}()

	fmt.Printf("[EDR/NDR] A pornit cu succes!\n")

	// Wait for Wails context to be cancelled
	<-ctx.Done()
	fmt.Println("[EDR/NDR] oprire agent (Wails context closed)!")
	return nil
}

func parseIp(family uint16, ip4 uint32, ip6 [16]byte) string {
	if family == unix.AF_INET {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, ip4)
		return ip.String()
	}
	return net.IP(ip6[:]).String()
}

func int8ToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		if v == 0 {
			return string(b[:i])
		}
		b[i] = byte(v)
	}
	return string(b)
}

func isLocalIP(ipStr string) bool {
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "0.0.0.0" || strings.HasPrefix(ipStr, "127.") {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	return false
}

func formatHexDump(data []byte) string {
	if len(data) == 0 {
		return "[NO PAYLOAD DATA CAPTURED IN THIS PACKET]"
	}
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		sb.WriteString(fmt.Sprintf("%04x  ", i))
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			sb.WriteString(fmt.Sprintf("%02x ", data[j]))
		}
		for j := end; j < i+16; j++ {
			sb.WriteString("   ")
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			b := data[j]
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
