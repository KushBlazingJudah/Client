package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Removed struct {
	ID    string
	Type  string
	Board string
}

func CreateLocalDeleteDB(db *sql.DB, id string, _type string) {
	rows, err := db.Query("select id from removed where id = $1", id)

	CheckError(err, "could not query removed")

	defer rows.Close()

	if rows.Next() {
		var i string

		rows.Scan(&i)

		if i != "" {
			_, err := db.Exec("update removed set type = $1 where id = $2", _type, id)

			CheckError(err, "Could not update removed post")

		}
	} else {
		_, err := db.Exec("insert into removed (id, type) values ($1, $2)", id, _type)

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
	rows, err := db.Query("select id, count from reported where id = $1 and board = $2", id, board)

	CheckError(err, "could not query reported")

	defer rows.Close()

	if rows.Next() {
		var i string
		var count int

		rows.Scan(&i, &count)

		if i != "" {
			count = count + 1

			_, err := db.Exec("update reported set count = $1 where id = $2", count, id)

			CheckError(err, "Could not update reported post")
		}
	} else {
		_, err := db.Exec("insert into reported (id, count, board) values ($1, $2, $3)", id, 1, board)

		CheckError(err, "Could not insert reported post")
	}

}

func GetLocalReportDB(db *sql.DB, board string) []Report {
	var reported []Report

	rows, err := db.Query("select id, count from reported where board = $1", board)

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
	_, err := db.Exec("delete from reported where id = ? and board = ?", id, board)

	CheckError(err, "Could not delete local report from db")
}
