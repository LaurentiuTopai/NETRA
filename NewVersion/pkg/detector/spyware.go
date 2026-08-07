package detector



import(
	"fmt"
	"time"
	"strings"
	"net"
	"edr-agent/pkg/response"
	"edr-agent/pkg/store"
	"context"
	"edr-agent/pkg/events"
)
const ExfilWindow = 10* time.Second

type HardwareBlockDetector struct{
	BlockCamera	bool
	BlockMicrophone bool
	BlockSpeaker	bool
	ctx	context.Context

}
func NewHardwareBlockDetector(cam,mic,spk bool,ctx context.Context) *HardwareBlockDetector{
	return & HardwareBlockDetector{
		BlockCamera: cam,
		BlockMicrophone : mic,
		BlockSpeaker: spk,
		ctx:	ctx,
	}

}
func (d *HardwareBlockDetector) OnDeviceOpen(pid uint32,comm string,filename string){
	if  store.IsCommWhiteListed(comm){ return}

	if d.BlockCamera && (strings.HasPrefix(filename,"/dev/video") || strings.HasPrefix(filename,"/dev/media")){
		fmt.Printf("[CAMERA] Pid:%d (%s) a incercat accesarea Camerei (%s)\n",pid,comm,filename)
		message := fmt.Sprintf("A accesat fisierul sensibil:%s",filename)
		response.QuarantineProcess(pid,comm)
		events.SendAlert(d.ctx,"[CAMERA][STOPED]",pid,comm,message)
		return
	}
	if d.BlockMicrophone && (strings.HasPrefix(filename,"/dev/snd/pcm")) && strings.HasSuffix(filename,"c"){
		fmt.Printf("[MICROFON] Pid:%d (%s) a incercat accesarea Microfonului (%s)\n",pid,comm,filename)
		message := fmt.Sprintf("A accesat fisierul sensibil:%s",filename)
		response.QuarantineProcess(pid,comm)
		events.SendAlert(d.ctx,"[MICROFON][STOPED]",pid,comm,message)
		return
	}
	if d.BlockSpeaker && (strings.HasPrefix(filename,"/dev/snd/pcm")) && strings.HasSuffix(filename,"p"){
		fmt.Printf("[DIFUZOR] Pid:%d (%s) a incercat accesarea Difuzorului (%s)\n",pid,comm,filename)
		message := fmt.Sprintf("A accesat fisierul sensibil:%s",filename)
		response.QuarantineProcess(pid,comm)
		events.SendAlert(d.ctx,"[DIFUZOR][STOPED]",pid,comm,message)
		return
	}
}

type SpywareDetector struct{
	store *store.ProcessStore
	ctx context.Context
}

func NewSpywareDetector(ps *store.ProcessStore,ctx context.Context) *SpywareDetector{
	return &SpywareDetector{	
			store:ps,
			ctx:ctx,
				}
}

func (d *SpywareDetector) OnSensitiveRead(pid uint32,comm string,filename string){
	if !store.IsSensitivePath(filename) || store.IsCommWhiteListed(comm){
		return;
	}
	d.store.UpdateSensitiveRead(pid,comm,filename)
	msg := fmt.Sprintf("A citit fisierul sensibil:%s",filename)

	fmt.Printf("[SPYWARE] Pid:%d (%s) a citit fisierul sensibil: %s!\n",
				   pid,comm,filename)

	events.SendAlert(d.ctx,"[SPYWARE][WARNING]",pid,comm,msg)

}
func (d *SpywareDetector) OnNetworkConnect(pid uint32,comm string,ipStr string,port uint16){
	p,exists := d.store.Get(pid)
	if port == 0 || ipStr == "::" || ipStr=="0.0.0.0"{
		return
	} 
	ip := net.ParseIP(ipStr)
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified(){
		return 
	}
	if !exists {
		return
	}
	if !p.LastSensitiveReadTime.IsZero() && time.Since(p.LastSensitiveReadTime) <= ExfilWindow{
		fmt.Printf("[SPYWARE] Pid:%d (%s) a citit %s acum %v si a incercat sa exfiltreze date catre %s:%d!\n",pid,comm,p.LastSensitiveReadFile,time.Since(p.LastSensitiveReadTime).Round(time.Millisecond),ipStr,port)
		msg := fmt.Sprintf("A citit fisierul sensibil:%s",p.LastSensitiveReadFile)
		//aici vine raspuns
		response.QuarantineProcess(pid,comm)
		events.SendAlert(d.ctx,"[SPYWARE][STOPED]",pid,comm,msg)
	}

}
