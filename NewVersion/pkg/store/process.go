package store


import(
	"net"
	"sync"
	"time"
)

type ProcessEntry struct{
	Pid	uint32
	Ppid	uint32
	Comm	string

	//Ransomware
	ModifiedFilesCount	int
	SuspiciousWritesCount	int
	WindowStart		time.Time
	WindowActual		time.Time
	LastFile		string	
	
	//Spyware
	LastSensitiveReadTime	time.Time
	LastSensitiveReadFile	string

	//Network
	LastNetworkTime		time.Time
	LastFamily		uint16
	LastPort		uint16
	LastIP			net.IP
}
type ProcessStore struct{
	mu			sync.RWMutex
	processes		 map[uint32]*ProcessEntry

}
func NewProcessStore()*ProcessStore{
	return &ProcessStore{
		processes:make(map[uint32]*ProcessEntry),
	}
}
//Creaza procesul daca nu exista sau il adauga daca exista
func (s *ProcessStore) GetOrAdd(pid uint32,ppid uint32,comm string)*ProcessEntry{
	s.mu.Lock()
	defer s.mu.Unlock()

	p,exists := s.processes[pid]
	if !exists{
		now := time.Now()
		p = & ProcessEntry{
				Pid:	pid,
				Ppid:	ppid,
				Comm:	comm,
				WindowStart:	now,
				WindowActual:	now,
		}
		s.processes[pid] = p
	}else if comm != ""{
		p.Comm = comm
	}
	return p
}
//Returneaza procesul pe baza pid-ului si daca exista in map
func (s *ProcessStore) Get(pid uint32)(*ProcessEntry,bool){
	s.mu.RLock()
	defer s.mu.RUnlock()

	p,exists := s.processes[pid]
	return p,exists
}
//Sterge procesul la iesire
func (s *ProcessStore) Remove(pid uint32){
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.processes,pid)
}
//actualizeaza contorul pentru scrieri la ransomeware
func (s *ProcessStore) UpdateFileWrite(pid uint32,comm string,filename string,timeWindow time.Duration)(int,bool){
	s.mu.Lock()
	defer s.mu.Unlock()

	p,exists := s.processes[pid]
	if !exists{
		now := time.Now()
		p = &ProcessEntry{
			Pid:	pid,
			Comm:	comm,
			WindowStart:	now,
			WindowActual:	now,
		}
		s.processes[pid]=p
	}
	now := time.Now()
	if now.Sub(p.WindowStart)>timeWindow{
		p.WindowStart = now
		p.SuspiciousWritesCount = 0
	}
	p.SuspiciousWritesCount++
	p.ModifiedFilesCount++
	p.LastFile = filename
	return p.SuspiciousWritesCount,true
}
func (s *ProcessStore) UpdateSensitiveRead(pid uint32,comm string,filename string,){
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	p,exists := s.processes[pid]
	if !exists{
		p = &ProcessEntry{
			Pid:pid,
			Comm:comm,
		}
		s.processes[pid]=p
	}
	p.LastSensitiveReadTime = now
	p.LastSensitiveReadFile = filename

}
