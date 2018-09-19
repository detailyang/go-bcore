package bcore

import (
	"fmt"
	"strings"
)

type Formatter struct {
	s   []string
	sep string
}

func NewFormatter(sep string) *Formatter {
	return &Formatter{sep: sep}
}

func (f *Formatter) PutField(field string, value interface{}) *Formatter {
	var text string

	switch value.(type) {
	case uint32:
		text = fmt.Sprintf("%s:%d", field, value)
	case Hash:
		text = fmt.Sprintf("%s:%s", field, value)
	default:
		panic("don't implement ")
	}
	f.s = append(f.s, text)

	return f
}

func (f *Formatter) String() string {
	return strings.Join(f.s, f.sep)
}
