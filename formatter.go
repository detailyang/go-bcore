package bcore

import (
	"fmt"
	"strings"
)

type Formatter struct {
	s     []string
	sep   string
	width int
}

func NewFormatter(sep string, width int) *Formatter {
	return &Formatter{sep: sep, width: width}
}

func (f *Formatter) PutField(field string, value interface{}) *Formatter {
	var text string

	switch value.(type) {
	case uint32:
		text = fmt.Sprintf("%-*s:%d", f.width, field, value)
	case Hash:
		text = fmt.Sprintf("%-*s:%s", f.width, field, value)
	case Compact:
		text = fmt.Sprintf("%-*s:%d", f.width, field, value)
	default:
		panic("don't implement ")
	}
	f.s = append(f.s, text)

	return f
}

func (f *Formatter) String() string {
	return strings.Join(f.s, f.sep)
}
