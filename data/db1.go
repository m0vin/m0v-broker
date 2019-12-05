package data

import (
	sq "database/sql"
	"fmt"
	_ "github.com/lib/pq"
        "github.com/golang/glog"
	//"golang.gurusys.co.uk/go-framework/sql"
	"time"
)

var (
	dbcon *DB
)

type dbaccount struct {
	New sq.NullInt64
	Old sq.NullInt64
}
type tenancyRequest struct {
	requestId uint64
	clientId  uint64
	mac       string
	updatedAt string
	implTime  string
	Accounts  []*dbaccount
}

func (t *tenancyRequest) String() string {
	return fmt.Sprintf("[%d]", t.requestId)
}

func GetDB() (*DB, error) {
	var err error

	if dbcon != nil {
		return dbcon, nil
	}
	dbcon, err = Open()
	if err != nil {
		return nil, err
	}
	return dbcon, nil
}

type Coordinate struct {
        Latitude float32
        Longitude float32
        Altitude float32
}

type Packet struct {
        Id int64 `json:"id!`
        Timestamp time.Time `json:"timestamp,omitempty"`
        Status bool `json:"status"`
        Voltage float64 `json:"voltage"`
        Frequency float64 `json:"freq"`
        Lat float64 `json:"lat"`
        Lng float64 `json:"lng"`
}

type Confo struct {
        Id int64 `json:"id`
        Devicename string `json:"devicename"`
        Ssid string `json:"ssid"`
        Hash int64 `json:"hash"`
        //Created int64 `json:"created,omitempty"`
        Created time.Time `json:"created,omitempty"`
}

type Pub struct {
        Id int64 `json:"id"`
        Latitude float32 `json:"latitude,omitempty"`
        Longitude float32 `json:"longitude,omitempty"`
        Altitude float32 `json:"altitude,omitempty"`
        Orientation float32 `json:"orientation,omitempty"`
        Hash int64 `json:"hash"`
        Created time.Time `json:"created,omitempty"`
        Creator int64 `json:"email"`
}

type Sub struct {
        Id int64 `json:"id"`
        Email string `json:"email"`
        Name string `json:"name"`
        Phone string `json:"phone"`
        Pswd string `json:"pswd"`
        Created time.Time `json:"created,omitempty"`
}

type WrappedCoordinate struct {
        UserId int64
        Id int64
        Latitude float32
        Longitude float32
        Altitude float32
        Timestamp string
        Track string
}

type TrackRequest struct {
	User int64
	//Period *TimePeriod
	Track  string
}

func PutPub(pub *Pub) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        // convert to timestamp
        //created, err := time.Unix(confo.Created, 0).MarshalText()
        created, err := pub.Created.MarshalText()
	if err != nil {
                glog.Error(err)
		created, err = time.Now().MarshalText()
	}
        result, err := db.Exec("insert into pub (latitude, longitude, altitude, orientation, created_at, hash, creator) values ($1, $2, $3, $4, $5, $6, $7)", pub.Latitude, pub.Longitude, pub.Altitude, pub.Orientation, string(created), pub.Hash, pub.Creator)
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("expected to affect 1 row, affected %d", rows)
                return uint64(rows) , err
        }
        return uint64(rows), nil
}

// UpdatePub a Pub using hash of provided Pub
func UpdatePub(pub *Pub) error {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return err
        }
        result, err := db.Exec("update pub set latitude = $1, longitude = $2, altitude = $3, orientation = $4, created_at = $5, creator = $7 where pub.Hash = $6", pub.Latitude, pub.Longitude, pub.Altitude, pub.Orientation, pub.Creator, pub.Hash, pub.Creator)
        if err != nil {
                glog.Error("Couldn't update pub %v\n", err)
                return err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("Expected to affect 1 row, affected %d", rows)
                return err
        }
        return nil
}

func GetPubByHash(hash int64) (*Pub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select pub_id, created_at, latitude, longitude, hash from pub where hash=$1 order by created_at desc limit 1", hash)
        if err != nil {
                glog.Errorf("data.GetPubByHash %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetPubByHash %v \n", err)
                return nil, fmt.Errorf("No data for hash: %d \n", hash)
        }
        pc := &Pub{}
        err = rows.Scan(&pc.Id, &pc.Created, &pc.Latitude, &pc.Longitude, &pc.Hash)
        if err != nil {
                glog.Errorf("data.GetPubByHash %v \n", err)
                return nil, err
        }
        return pc, nil
}

func GetPubs(limit int) ([]*Pub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select pub_id, created_at, latitude, longitude, hash from pub order by created_at desc limit $1", limit)
        if err != nil {
                glog.Errorf("data.GetPubs %v \n", err)
                return nil, err
        }
        defer rows.Close()
        /*if !rows.Next() {
                glog.Errorf("data.GetPubs no rows \n")
                return nil, fmt.Errorf("No data for pub \n")
        }*/
        pbs := make([]*Pub, 0)
        for rows.Next() {
                pb := &Pub{}
                if err := rows.Scan(&pb.Id, &pb.Created, &pb.Latitude, &pb.Longitude, &pb.Hash); err != nil {
                        glog.Errorf("data.GetPubs %v \n", err)
                        return pbs, fmt.Errorf("No data for pubs \n")
                }
                glog.Infof("data.GetPubs appending \n")
                pbs = append(pbs, pb)
        }
        return pbs, nil
}

func GetPubsForSub(email string) ([]*Pub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select pub.pub_id, created_at, latitude, longitude, hash from pub inner join subpub on subpub.pub_id = pub.pub_id order by created_at desc limit $1", 10)
        if err != nil {
                glog.Errorf("data.GetPubs %v \n", err)
                return nil, err
        }
        defer rows.Close()
        /*if !rows.Next() {
                glog.Errorf("data.GetPubs no rows \n")
                return nil, fmt.Errorf("No data for pub \n")
        }*/
        pbs := make([]*Pub, 0)
        for rows.Next() {
                pb := &Pub{}
                if err := rows.Scan(&pb.Id, &pb.Created, &pb.Latitude, &pb.Longitude, &pb.Hash); err != nil {
                        glog.Errorf("data.GetPubs %v \n", err)
                        return pbs, fmt.Errorf("No data for pubs \n")
                }
                glog.Infof("data.GetPubs appending \n")
                pbs = append(pbs, pb)
        }
        return pbs, nil
}

func PutSub(sub *Sub) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        // convert to timestamp
        //created, err := time.Unix(confo.Created, 0).MarshalText()
        created, err := sub.Created.MarshalText()
	if err != nil || sub.Created.Before(time.Date(2000,1,1,1,1,1,1,time.UTC)) {
                glog.Error(err)
		created, err = time.Now().MarshalText()
	}
        result, err := db.Exec("insert into sub (email, phone, name, pswd, created_at) values ($1, $2, $3, $4, $5)", sub.Email, sub.Phone, sub.Name, sub.Pswd, string(created))
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("expected to affect 1 row, affected %d", rows)
                return uint64(rows) , err
        }
        return uint64(rows), nil
}

func GetSubByEmail(email string) (*Sub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select sub_id, created_at, email, name, phone from sub where email=$1 order by created_at desc limit 1", email)
        if err != nil {
                glog.Errorf("data.GetSubByEmail %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetSubByEmail %v \n", err)
                return nil, fmt.Errorf("No data for email: %s \n", email)
        }
        pc := &Sub{}
        err = rows.Scan(&pc.Id, &pc.Created, &pc.Email, &pc.Name, &pc.Phone)
        if err != nil {
                glog.Errorf("data.GetSubByEmail %v \n", err)
                return nil, err
        }
        return pc, nil
}

func CheckPswd(email string, pswd string) bool {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return false
        }
        rows, err := db.Query("select sub_id, email, pswd from sub where email=$1 order by created_at desc limit 1", email)
        if err != nil {
                glog.Errorf("data.CheckPswd %v \n", err)
                return false
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.CheckPswd %v \n", err)
                return false
        }
        pc := &Sub{}
        err = rows.Scan(&pc.Id, &pc.Email, &pc.Pswd)
        if err != nil {
                glog.Errorf("data.CheckPswd %v \n", err)
                return false
        }
        if pc.Pswd != pswd {
                return false
        }
        return true
}

func GetSubs(limit int) ([]*Sub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select sub_id, created_at, email, name, phone from sub order by created_at desc limit $1", limit)
        if err != nil {
                glog.Errorf("data.GetSubs %v \n", err)
                return nil, err
        }
        defer rows.Close()
        /*if !rows.Next() {
                glog.Errorf("data.GetPubs no rows \n")
                return nil, fmt.Errorf("No data for pub \n")
        }*/
        pbs := make([]*Sub, 0)
        for rows.Next() {
                pb := &Sub{}
                if err := rows.Scan(&pb.Id, &pb.Created, &pb.Email, &pb.Name, &pb.Phone); err != nil {
                        glog.Errorf("data.GetSubs %v \n", err)
                        return pbs, fmt.Errorf("No data for subs \n")
                }
                glog.Infof("data.GetSubs appending \n")
                pbs = append(pbs, pb)
        }
        return pbs, nil
}

// PutCsub persists an unknown Sub with unregistered email which may be part of a confo from device
func PutCsub(sub *Sub) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        result, err := db.Exec("insert into csub (email) values ($1)", sub.Email)
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("expected to affect 1 row, affected %d", rows)
                return uint64(rows) , err
        }
        return uint64(rows), nil
}

func GetCsubByEmail(email string) (*Sub, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select sub_id, created_at, email from csub where email=$1 order by created_at desc limit 1", email)
        if err != nil {
                glog.Errorf("data.GetCsubByEmail %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetCsubByEmail %v \n", err)
                return nil, fmt.Errorf("No data for email: %s \n", email)
        }
        pc := &Sub{}
        err = rows.Scan(&pc.Id, &pc.Created, &pc.Email)
        if err != nil {
                glog.Errorf("data.GetCsubByEmail %v \n", err)
                return nil, err
        }
        return pc, nil
}

// PutConf inserts a recd. Conf in db. 
func PutConfo(confo *Confo) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        // convert to timestamp
        //created, err := time.Unix(confo.Created, 0).MarshalText()
        created, err := confo.Created.MarshalText()
	if err != nil {
                glog.Error(err)
		created, err = time.Now().MarshalText()
	}
        result, err := db.Exec("insert into confo (devicename, ssid, created_at, hash) values ($1, $2, $3, $4)", confo.Devicename, confo.Ssid, string(created), confo.Hash)
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("expected to affect 1 row, affected %d", rows)
                return uint64(rows) , err
        }
        return uint64(rows), nil
}

// GetLastConf retrieves the latest conf in db with supplied `ssid+devicename`. 
// It returns a *Conf with matching `ssid+devicename` and latest timestamp or nil, error if none found
func GetLastConfo(devicename, ssid string) (*Confo, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select devicename, ssid, created_at from confo where devicename=$1 and ssid=$2 order by created_at desc limit 1", devicename, ssid)
        if err != nil {
                glog.Errorf("data.GetLastConfo %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetLastConfo %v \n", err)
                return nil, fmt.Errorf("No data for tuple: %s %s \n", devicename, ssid)
        }
        pc := &Confo{}
        err = rows.Scan(&pc.Devicename, &pc.Ssid, &pc.Created)
        if err != nil {
                glog.Errorf("data.GetLastConfo %v \n", err)
                return nil, err
        }
        return pc, nil
}

func GetLastConfoWithHash(hash int64) (*Confo, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select devicename, ssid, created_at from confo where hash=$1 order by created_at desc limit 1", hash)
        if err != nil {
                glog.Errorf("data.GetLastConfoWithHash %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetLastConfoWithHash %v \n", err)
                return nil, fmt.Errorf("No data for : %d \n", hash)
        }
        pc := &Confo{}
        err = rows.Scan(&pc.Devicename, &pc.Ssid, &pc.Created)
        if err != nil {
                glog.Errorf("data.GetLastConfoWithHash %v \n", err)
                return nil, err
        }
        return pc, nil
}

// PutPacket inserts packet in db. It *should* check whether pub_id sent with packet is from the 'correct' pub. This could be a check against the location or a 'secret' decided during configuration with app which is sent along with each packet'
func PutPacket(packet *Packet) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        result, err := db.Exec("insert into packet (pub_hash, created_at, voltage, frequency, protected) values ($1, $2, $3, $4, $5)", packet.Id, packet.Timestamp, packet.Voltage, packet.Frequency, packet.Status)
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
        if rows != 1 {
                glog.Error("expected to affect 1 row, affected %d", rows)
                return uint64(rows) , err
        }
        return uint64(rows), nil
}

// GetPacket retrieves the latest packet in db with supplied `pub_hash`. 
// Note: it returns a packet with `id` set to the serial of the reading rather than `pub_hash` since caller of function already has `pub_hash`
func GetLastPacket(pubHash int64) (*Packet, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select id, created_at, voltage, frequency, protected from packet where pub_hash=$1 order by created_at desc limit 1", pubHash)
        if err != nil {
                glog.Errorf("data.GetLastPacket %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetLastPacket %v \n", err)
                return nil, fmt.Errorf("No data for user: %d \n", pubHash)
        }
        pc := &Packet{Id: pubHash}
        err = rows.Scan(&pc.Id, &pc.Timestamp, &pc.Voltage, &pc.Frequency, &pc.Status)
        if err != nil {
                glog.Errorf("data.GetLastPacket %v \n", err)
                return nil, err
        }
        return pc, nil
}

// PutCoordinate
func PutCoordinate(coord *WrappedCoordinate) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        //result, err := db.Exec("insert into coordinate (user_id, latitude, longitude, altitude, created_at) values ($1, $2, $3, $4, $5)", coord.UserId, coord.Latitude, coord.Longitude, coord.Altitude, coord.Timestamp)
        result, err := db.Exec("insert into coordinate (user_id, latitude, longitude, altitude, track) values ($1, $2, $3, $4, $5)", coord.UserId, coord.Latitude, coord.Longitude, coord.Altitude, coord.Track)
        if err != nil {
                glog.Error(err)
                return 0 , err
        }
        rows, err := result.RowsAffected()
                if rows != 1 {
                        glog.Error("expected to affect 1 row, affected %d", rows)
                        return uint64(rows) , err
                }
        return uint64(rows), nil
}

func GetCoordinate(userid int64) (*WrappedCoordinate, error){
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select id, latitude, longitude, altitude from coordinate where user_id=$1 order by created_at desc limit 1", userid)
        if err != nil {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return nil, fmt.Errorf("No data for user: %d \n", userid)
        }
        wc := &WrappedCoordinate{UserId: userid}
        err = rows.Scan(&wc.Id, &wc.Latitude, &wc.Longitude, &wc.Altitude)
        if err != nil {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return nil, err
        }
        return wc, nil
}

func GetTrack(tr *TrackRequest) ([]*Coordinate, error){
        cs := make([]*Coordinate, 0)
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return cs, err
        }
        if tr.User == 0 || tr.Track == ""{
                return nil, fmt.Errorf("Invalid user or track")
        }
        rows, err := db.Query("select latitude, longitude, altitude from coordinate where user_id=$1and track=$2 order by created_at asc", tr.User, tr.Track)
        if err != nil {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return cs, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return cs, fmt.Errorf("No data for user, track: %d %s \n", tr.User, tr.Track)
        }
        for rows.Next() {
                c := &Coordinate{}
                if err := rows.Scan(&c.Latitude, &c.Longitude, &c.Altitude); err != nil {
                        glog.Errorf("data.GetCoordinate %v \n", err)
                        return cs, fmt.Errorf("No data for user: %d \n", tr.User)
                }
                cs = append(cs, c)
        }
        return cs, nil
}

type ChangeLog struct {
	ID          uint64
	ClientId    uint64
	Status      string
	Mac         sq.NullString
	HesAccount1 sq.NullInt64
	HesAccount2 sq.NullInt64
	HesAccount3 sq.NullInt64
	HesAccount4 sq.NullInt64
	HesAccount5 sq.NullInt64
}

// get a request by id
func GetFromStore(requestid uint64) (*ChangeLog, error) {
	if *debug {
		fmt.Printf("Getting value for requestid %d \n", requestid)
	}
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to get item, no db: %s\n", err)
		}
		// can't do stuff...
		return nil, err
	}
	rows, err := db.Query("select request_id,client_id, mac,status, new_hes_account1, new_hes_account2, new_hes_account3, new_hes_account4, new_hes_account5 from change_tenancy_log where request_id=$1", requestid)
	if err != nil {
		if *debug {
			fmt.Printf("Failed to query for requestid %d:%s\n", requestid, err)
		}
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if *debug {
			fmt.Printf("No request with id %d", requestid)
		}
		return nil, fmt.Errorf("No request with id %d", requestid)
	}
	cl := ChangeLog{ClientId: 0, Status: "PENDING"}
	err = rows.Scan(&cl.ID, &cl.ClientId, &cl.Mac, &cl.Status, &cl.HesAccount1, &cl.HesAccount2, &cl.HesAccount3, &cl.HesAccount4, &cl.HesAccount5)
	if err != nil {
		if *debug {
			fmt.Printf("a) failed to scan row: %s\n", err)
		}
		return nil, fmt.Errorf("a) Failed to scan row (%v)", err)
	}
	return &cl, nil
}

// save a request with client id & mac address.
// returns ID or error
// if bool is true it indicates that an entry already exists for the mac provided
func PutToStore(mac string, clientId int64) (uint64, bool, error) {
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to put item, no db: %s\n", err)
		}
		return 0, false, err
	}
	now := time.Now().Round(time.Second)
	nowp4 := now.Add(time.Minute * time.Duration(*implTime)).Round(time.Second)
	createdAt, err := now.MarshalText()
	if err != nil {
		return 0, false, err
	}
	updatedAt := createdAt
	var implTime []byte
	implTime, err = nowp4.MarshalText()
	if err != nil {
		return 0, false, err
	}
	rows, err := db.Query("insert into change_tenancy_log (client_id, mac, created_at, updated_at, status, impl_time) values ($1,$2,$3,$4,$5,$6) RETURNING request_id ", clientId, mac, createdAt, updatedAt, "PENDING", string(implTime))
	if err != nil {
		if db.CheckDuplicateRowError(err) {
			if *debug {
				fmt.Printf("Entry for %s already exists (%v)", mac, err)
				return 0, true, nil
			}
		}

		if *debug {
			fmt.Printf("Failed to insert into store: %s\n", err)
		}
		return 0, false, fmt.Errorf("post failed (%s)", err)
	}
	var id uint64
	defer rows.Close()
	if !rows.Next() {
		return 0, false, fmt.Errorf("No rows returned for new change request")
	}
	err = rows.Scan(&id)
	if err != nil {
		if *debug {
			fmt.Printf("Failed to get id for new changerequest:%s\n", err)
		}
		return 0, false, fmt.Errorf("no id for new changerequest (%s)", err)
	}
	logRequestUpdate(id, "PENDING")
	return id, false, nil
}

// get pending requests - returns (list of pending, nil error) or (nil, err)
func getPending() ([]tenancyRequest, error) {
	return getByStatus("PENDING")
}

// get pending requests - returns (list of pending, nil error) or (nil, err)
func getAccepted() ([]tenancyRequest, error) {
	return getByStatus("ACCEPTED")
}
func getByStatus(status string) ([]tenancyRequest, error) {
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to get pending, no db: %s\n", err)
		}
		return nil, err
	}

	var qry string
	switch status {
	case "ACCEPTED":
		qry = "select request_id, client_id, mac, updated_at, impl_time,new_hes_account1,new_hes_account2,new_hes_account3,new_hes_account4,new_hes_account5,old_hes_account1,old_hes_account2,old_hes_account3,old_hes_account4,old_hes_account5 from change_tenancy_log where status=$1 and impl_time < now() limit 100"
	default:
		qry = "select request_id, client_id, mac, updated_at, impl_time,new_hes_account1,new_hes_account2,new_hes_account3,new_hes_account4,new_hes_account5,old_hes_account1,old_hes_account2,old_hes_account3,old_hes_account4,old_hes_account5 from change_tenancy_log where status=$1 limit 100"
	}
	rows, err := db.Query(qry, status)
	if err != nil {
		fmt.Printf("failed to get pending")
		return nil, err
	}
	defer rows.Close()

	// trs := make([]tenancyRequest, 100) // will create 100 requests, but only initialise however many the query returns. leads to subsequent errors
	var trs []tenancyRequest
	for rows.Next() {
		tr := tenancyRequest{}
		for i := 0; i < 5; i++ {
			tr.Accounts = append(tr.Accounts, &dbaccount{})
		}
		err := rows.Scan(&tr.requestId, &tr.clientId, &tr.mac, &tr.updatedAt, &tr.implTime, &tr.Accounts[0].New, &tr.Accounts[1].New, &tr.Accounts[2].New, &tr.Accounts[3].New, &tr.Accounts[4].New, &tr.Accounts[0].Old, &tr.Accounts[1].Old, &tr.Accounts[2].Old, &tr.Accounts[3].Old, &tr.Accounts[4].Old)
		if err != nil {
			if *debug {
				fmt.Printf("b) Failed to scan row: %v\n", err)
			}
			return nil, err
		}
		trs = append(trs, tr)
	}

	return trs, nil
}

type HesAccountResponse struct {
	New uint64
	Old uint64
}

// updateRequest updates the status of the request returning nil on success
// hes returns a json array. My assumption is that implementation requires the array
// to remain in a specified order. Presumably the position in the array is
// intented to reflect the HubAccountNumber(1..5)
func updateAccounts(requestId uint64, a []*HesAccountResponse) error {
	// this is fantastic. seen hes return 2 accounts and 150 accounts. whatever...
	for len(a) < 5 {
		a = append(a, &HesAccountResponse{})
	}
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to update item, no db: %s\n", err)
		}
		// can't do stuff...
		return err
	}
	// postgres wont return anything useful (e.g. no AffectedRows())
	_, err = db.Exec("update change_tenancy_log set new_hes_account1 = $1, new_hes_account2 = $2, new_hes_account3 = $3, new_hes_account4 = $4, new_hes_account5 = $5, old_hes_account1 = $6, old_hes_account2 = $7, old_hes_account3 = $8, old_hes_account4 = $9, old_hes_account5 = $10 where request_id=$11", a[0].New, a[1].New, a[2].New, a[3].New, a[4].New, a[0].Old, a[1].Old, a[2].Old, a[3].Old, a[4].Old, requestId)
	if err != nil {
		return err
	}
	return nil
}

// updateRequest updates the status of the request returning nil on success
func UpdateRequest(requestId uint64, status string) error {
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to update item, no db: %s\n", err)
		}
		// can't do stuff...
		return err
	}
	r, err := db.Exec("update change_tenancy_log set status = $1 where request_id>$2", status, requestId)
	if err != nil {
		return err
	}
	logRequestUpdate(requestId, status)
	// Note: postgres driver does not support RowsAffected()
	var n int64
	if n, err = r.RowsAffected(); n == 0 || err != nil {
		if err != nil {
			return err
		} else {
			return fmt.Errorf("Rows affected: %v \n", n)
		}
	}
	fmt.Println("rows %d \n", n)
	return nil
}

func logRequestUpdate(requestId uint64, status string) {
	db, err := GetDB()
	if err != nil {
		if *debug {
			fmt.Printf("failed to get pending, no db: %s\n", err)
		}
		return
	}

	cl, err := GetFromStore(requestId)
	if err != nil {
		fmt.Printf("Unable to get request %d : %s\n", requestId, err)
		return
	}
	_, err = db.Exec("insert into cot_log (request_id,newstatus,occured,mac) values ($1,$2,NOW(),$3)", requestId, status, cl.Mac)
	if err != nil {
		fmt.Printf("Failed to update logrequestupdate (%d,%s): %s\n", requestId, status, err)
	}
}
