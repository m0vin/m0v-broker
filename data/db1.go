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
        Timestamp int64 `json:"timestamp,omitempty"`
        Status bool `json:"status"`
        Voltage float64 `json:"voltage"`
        Frequency float64 `json:"freq"`
        Lat float64 `json:"lat"`
        Lng float64 `json:"lng"`
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

// PutPacket inserts packet in db. It *should* check whether pub_id sent with packet is from the 'correct' pub. This could be a check against the location or a 'secret' decided during configuration with app which is sent along with each packet'
func PutPacket(packet *Packet) (uint64, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return 0, err
        }
        result, err := db.Exec("insert into packet (pub_id, voltage, frequency, protected) values ($1, $2, $3, $4)", packet.Id, packet.Voltage, packet.Frequency, packet.Status)
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

// GetPacket retrieves the latest packet in db with supplied `pub_id`. 
// Note: it returns a packet with `id` set to the serial of the reading rather than `pub_id` since caller of function already has `pub_id`
func GetLastPacket(pubId int64) (*Packet, error) {
        db, err := GetDB()
        if err != nil {
                glog.Error(err)
                return nil, err
        }
        rows, err := db.Query("select id, voltage, frequency, protected from packet where pub_id=$1 order by created_at desc limit 1", pubId)
        if err != nil {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return nil, err
        }
        defer rows.Close()
        if !rows.Next() {
                glog.Errorf("data.GetCoordinate %v \n", err)
                return nil, fmt.Errorf("No data for user: %d \n", pubId)
        }
        pc := &Packet{Id: pubId}
        err = rows.Scan(&pc.Id, &pc.Voltage, &pc.Frequency, &pc.Status)
        if err != nil {
                glog.Errorf("data.GetCoordinate %v \n", err)
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
