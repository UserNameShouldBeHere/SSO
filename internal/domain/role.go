package domain

type Role struct {
	Name        string
	Level       uint32
	Permissions []string
}
