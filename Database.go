package main

import "fmt"
import "database/sql"
import _ "github.com/lib/pq"

type Removed struct {
	ID string
	Type string
	Board string
}

func CreateLocalDeleteDB(db *sql.DB, id string, _type string)	{
	query := fmt.Sprintf("select id from removed where id='%s'", id)

	rows, err := db.Query(query)

	CheckError(err, "could not query removed")

	defer rows.Close()

	if rows.Next() {
		var i string

		rows.Scan(&i)

		if i != "" {
			query := fmt.Sprintf("update removed set type='%s' where id='%s'", _type, id)

			_, err := db.Exec(query)
			
			CheckError(err, "Could not update removed post")
			
		}
	} else {
		query := fmt.Sprintf("insert into removed (id, type) values ('%s', '%s')", id, _type)
		
		_, err := db.Exec(query)
		
		CheckError(err, "Could not insert removed post")
	}
}

func GetLocalDeleteDB(db *sql.DB) []Removed {
	var deleted []Removed
	
	query := fmt.Sprintf("select id, type from removed")

	rows, err := db.Query(query)

	CheckError(err, "could not query removed")

	defer rows.Close()

	for rows.Next() {
		var r Removed

		rows.Scan(&r.ID, &r.Type)

		deleted = append(deleted, r)
	}

	return deleted
}

func CreateLocalReportDB(db *sql.DB, id string, board string) {
	query := fmt.Sprintf("select id, count from reported where id='%s' and board='%s'", id, board)

	rows, err := db.Query(query)

	CheckError(err, "could not query reported")

	defer rows.Close()

	if rows.Next() {
		var i string
		var count int

		rows.Scan(&i, &count)

		if i != "" {
			count = count + 1
			query := fmt.Sprintf("update reported set count='%d' where id='%s'", count, id)

			_, err := db.Exec(query)
			
			CheckError(err, "Could not update reported post")
		}
	} else {
		query := fmt.Sprintf("insert into reported (id, count, board) values ('%s', '%d', '%s')", id, 1, board)
		
		_, err := db.Exec(query)
		
		CheckError(err, "Could not insert reported post")
	}	

}

func GetLocalReportDB(db *sql.DB, board string) []Report {
	var reported []Report
	
	query := fmt.Sprintf("select id, count from reported where board='%s'", board)

	rows, err := db.Query(query)

	CheckError(err, "could not query reported")

	defer rows.Close()

	for rows.Next() {
		var r Report

		rows.Scan(&r.ID, &r.Count)

		reported = append(reported, r)
	}

	return reported
}

func CloseLocalReportDB(db *sql.DB, id string, board string) {
	query := fmt.Sprintf("delete from reported where id='%s' and board='%s'", id, board)

	_, err := db.Exec(query)

	CheckError(err, "Could not delete local report from db")
}
