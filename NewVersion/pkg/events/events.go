package events

import(
	"context"
	"time"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type EDRAlert struct{
	Type		string `json:"type"`
	Pid		uint32 `json:"pid"`
	Comm		string `json:"comm"`
	Message		string `json:"message"`
	Timestamp	string `json:"timestamp"`
}

func SendAlert(ctx context.Context,alertType string,pid uint32,comm string,message string){

	if ctx == nil{ return}

	alert := EDRAlert{
		Type:		alertType,
		Pid:		pid,
		Comm:		comm,
		Message:	message,
		Timestamp:	time.Now().Format("15:04:05"),
	}
	runtime.EventsEmit(ctx,"edr:alert",alert)
}

