package response


import(
	"fmt"
	"syscall"
)

func QuarantineProcess(pid uint32,comm string) error{
	fmt.Printf("SIGSTOP pe procesul : %d (%s)!\n",pid,comm)
	err := syscall.Kill(int(pid),syscall.SIGSTOP)
	if err != nil{
		return fmt.Errorf("erroare la aplicarea carantinei pe PID %d: %w",pid,err)
	}
	return nil
}
func KillProcess(pid uint32,comm string) error{
	fmt.Printf("SIGKILL pe procesul : %d (%s)!\n",pid,comm)
	err := syscall.Kill(int(pid),syscall.SIGKILL)
	if err != nil{
		return fmt.Errorf("erroare la aplicarea KILL pe PID %d: %w",pid,err)
	}
	return nil
}



