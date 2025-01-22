package domain

import "time"

type User struct {
	Uuid             string
	Name             string
	Email            string
	PermissionsLevel uint32
	RegisteredAt     time.Time
}
