// Code generated by "stringer -type Command ."; DO NOT EDIT.

package snmp

import "strconv"

const _Command_name = "GetGetNextResponseSetTrapGetBulk"

var _Command_index = [...]uint8{0, 3, 10, 18, 21, 25, 32}

func (i Command) String() string {
	i -= 160
	if i < 0 || i >= Command(len(_Command_index)-1) {
		return "Command(" + strconv.FormatInt(int64(i+160), 10) + ")"
	}
	return _Command_name[_Command_index[i]:_Command_index[i+1]]
}
