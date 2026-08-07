package agent

import (
	"context"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"edr-agent/pkg/detector"
	"edr-agent/pkg/store"
)

// Directive bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type filer_event filer ../kernel/filer.bpf.c -- -I../kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type exit_event edr ../kernel/edr.bpf.c -- -I../kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type network_event network ../kernel/network.bpf.c -- -I../kernel



func Start(ctx context.Context) error {
	//1.Permisiuni pentru memorie
	if err := rlimit.RemoveMemlock();err!=nil{

		log.Fatalf("Erroare memlock: %v\n",err)
	}
	
	//2.InitializareStocare
	procStore := store.NewProcessStore()
	ransomwareDet := detector.NewRansomewareDetector(procStore)
	spywareDet := detector.NewSpywareDetector(procStore, ctx)
	hardwareDet := detector.NewHardwareBlockDetector(true,true,true, ctx)
	//3.Incarcare eBPF
	var edrObjs edrObjects
	if err := loadEdrObjects(&edrObjs,nil);err != nil{
		log.Fatalf("Erroare incarcare EDR eBPF: %v\n",err)
	}
	defer edrObjs.Close()

	var filerObjs filerObjects
	if err:= loadFilerObjects(&filerObjs,nil);err != nil{
		log.Fatalf("Erroare incarcare Filer eBPF: %v\n",err)
	}
	defer filerObjs.Close()

	var networkObjs networkObjects
	if err:= loadNetworkObjects(&networkObjs,nil);err!= nil{
		log.Fatalf("Erroare incarcare Network eBPF: %v\n",err)
	}
	defer networkObjs.Close()
	
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

	rbFiler,err := ringbuf.NewReader(filerObjs.Rb)
	if err != nil{
		log.Fatalf("Erroare deschidere Filer RingBuffer: %v",err)
	}
	defer rbFiler.Close()
	rbNetwork,err := ringbuf.NewReader(networkObjs.Rb)
	if err != nil{
		log.Fatalf("Erroare deschidere Network RingBuffer: %v",err)
	}
	defer rbNetwork.Close()
	rbEdrExit,err := ringbuf.NewReader(edrObjs.ExitRb)
	if err != nil{
		log.Fatalf("Erroare deschidere Exit RingBuffer: %v",err)
	}
	defer rbEdrExit.Close()





	go func(){
		var event filerFilerEvent
		for{
			record,err := rbFiler.Read()
			if err != nil{
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian,&event);err!=nil{
				continue
			}
			comm := int8ToString(event.Comm[:])
			filename := int8ToString(event.Filename[:])

			isWrite := (event.Flags & unix.O_ACCMODE) == unix.O_WRONLY || (event.Flags & unix.O_ACCMODE) == unix.O_RDWR
			isRead := (event.Flags & unix.O_ACCMODE) == unix.O_RDONLY || (event.Flags & unix.O_ACCMODE ) == unix.O_RDWR
			
			if(isWrite){
				ransomwareDet.OnFileWrite(event.Pid,comm,filename)
			}
			if(isRead){
				spywareDet.OnSensitiveRead(event.Pid,comm,filename)
				hardwareDet.OnDeviceOpen(event.Pid,comm,filename)			
		}



		}

	}()

	go func(){
		var event networkNetworkEvent
		for{
			record,err := rbNetwork.Read()
			if err != nil{
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian,&event);err!=nil{
				continue
			}
			comm := int8ToString(event.Comm[:])
			ipStr := parseIp(event.Family,event.Ip4,event.Ip6)
			spywareDet.OnNetworkConnect(event.Pid,comm,ipStr,event.Port)
		}

	}()

	go func(){
		var event edrExitEvent
		for{
			record,err := rbEdrExit.Read()
			if err != nil{
				return
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian,&event);err!=nil{
				continue
			}
			procStore.Remove(event.Pid)
		}
	}()
	fmt.Printf("[EDR] A pornit cu succes!\n")

	// Wait for Wails context to be cancelled
	<-ctx.Done()
	fmt.Println("[EDR] oprire agent (Wails context closed)!")
	return nil
}
func parseIp(family uint16,ip4 uint32,ip6 [16]byte) string{
		if family == unix.AF_INET{
			ip := make(net.IP,4)
			binary.LittleEndian.PutUint32(ip,ip4)
			return ip.String()
		}
		return net.IP(ip6[:]).String()

}
func int8ToString(arr []int8) string{
	b := make([] byte,len(arr))
	for i,v := range arr{
		if v == 0 {
			return string(b[:i])
		}
		b[i] = byte(v)
	}
	return string(b)
}
