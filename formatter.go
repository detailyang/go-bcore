package bcore

import (
	"fmt"
	"strings"

	. "github.com/detailyang/go-bprimitives"
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
	case uint64:
		text = fmt.Sprintf("%-*s:%d", f.width, field, value)
	case uint32:
		text = fmt.Sprintf("%-*s:%d", f.width, field, value)
	case Hash:
		text = fmt.Sprintf("%-*s:%s", f.width, field, value)
	case Compact:
		text = fmt.Sprintf("%-*s:%d", f.width, field, value)
	case string:
		text = fmt.Sprintf("%-*s:%s", f.width, field, value)
	default:
		panic("don't implement ")
	}
	f.s = append(f.s, text)

	return f
}

func (f *Formatter) PutListField(field string, value []fmt.Stringer) *Formatter {
	for i, s := range value {
		label := fmt.Sprintf("%s[%d]", field, i)
		text := fmt.Sprintf("%-*s:\n%s", f.width, label, s.String())
		f.s = append(f.s, text)
	}

	return f
}

func (f *Formatter) String() string {
	return strings.Join(f.s, f.sep)
}
