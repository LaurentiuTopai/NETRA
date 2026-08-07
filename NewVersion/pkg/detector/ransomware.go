package detector


import(
	"fmt"
	"time"

	"edr-agent/pkg/response"
	"edr-agent/pkg/store"
)
const(
	MaxWritesAllowed = 20
	TimeWindow = 1 * time.Second
)

type RansomewareDetector struct{
	store *store.ProcessStore
}

func NewRansomewareDetector(ps *store.ProcessStore) *RansomewareDetector{
	return &RansomewareDetector{
		store:ps,
	}
}

func (d *RansomewareDetector) OnFileWrite(pid uint32,comm string,filename string){
		if store.IsCommWhiteListed(comm) || store.IsPathWhiteListed(filename){
			return 
		}
		writeCount,_ := d.store.UpdateFileWrite(pid,comm,filename,TimeWindow)

		if writeCount > MaxWritesAllowed {
			fmt.Printf("[RANSOMEWARE] PID:%d (%s) a scris %d fisiere in %v secunde\n",
						       pid,comm,writeCount,TimeWindow)
			//aici vine sigstop imd
			response.QuarantineProcess(pid,comm)
		}

}




