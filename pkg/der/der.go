package der

import (
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"sort"
)

var ErrInvalidType = fmt.Errorf("invalid type")

type Tag uint64

const (
	Bool   Tag = 0x01
	Int    Tag = 0x02
	String Tag = 0x0c

	Array  Tag = 0x30
	Object Tag = 0x31

	ApplicationObject Tag = 0x70
)

// encodeLength encodes n using a leading byte indicating the length of n in bytes if n >= 128
func encodeLength(n uint64) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}

	out := make([]byte, 0)

	size := (64 - bits.LeadingZeros64(n) + 7) / 8
	out = append(out, 0x80|byte(size))
	size *= 8

	for size != 0 {
		out = append(out, byte((n>>(size-8))&0xFF))
		size -= 8
	}

	return out
}

func decodeLength(buf []byte) (int, uint64) {
	if buf[0]&0x80 == 0 {
		return 1, uint64(buf[0])
	}

	size := int(buf[0] &^ 0x80)

	n := uint64(0)
	for i := 0; i < size; i++ {
		n <<= 8
		n |= uint64(buf[i+1])
	}

	return size + 1, n
}

func encodeBool(b bool) []byte {
	if b {
		return []byte{byte(Bool), 1, 1}
	} else {
		return []byte{byte(Bool), 1, 0}
	}
}

func decodeBool(data []byte) (bool, int, error) {
	if len(data) < 3 {
		return false, 0, fmt.Errorf("data too short to decode bool: %w", io.ErrUnexpectedEOF)
	}

	if Tag(data[0]) != Bool {
		return false, 0, fmt.Errorf("expected bool tag, got 0x%02x: %w", Tag(data[0]), ErrInvalidType)
	}

	if data[1] != 1 {
		return false, 0, fmt.Errorf("invalid bool length %v: %w", data[1], ErrInvalidType)
	}

	switch data[2] {
	case 0:
		return false, 3, nil
	default:
		return true, 3, nil
	}
}

func encodeInt(n int64, size uint64) []byte {
	out := make([]byte, 0)
	out = append(out, byte(Int))
	out = append(out, encodeLength(uint64(size))...)

	size *= 8

	for size != 0 {
		size -= 8
		out = append(out, byte((n>>size)&0xFF))
	}

	return out
}
func decodeInt(data []byte) (int64, int, error) {
	if len(data) < 3 {
		return 0, 0, fmt.Errorf("data too short to decode int: %w", io.ErrUnexpectedEOF)
	}

	if Tag(data[0]) != Int {
		return 0, 0, fmt.Errorf("expected int tag, got 0x%02x: %w", Tag(data[0]), ErrInvalidType)
	}

	offset, length := decodeLength(data[1:])
	offset += 1 // tag

	var ret int64
	for i := 0; i < int(length); i++ {
		ret <<= 8
		ret |= int64(data[offset+i])
	}

	return ret, offset + int(length), nil
}

func encodeString(s string) []byte {
	out := make([]byte, 0)
	out = append(out, byte(String))

	out = append(out, encodeLength(uint64(len(s)))...)
	out = append(out, []byte(s)...)

	return out
}

func decodeString(data []byte) (string, int, error) {
	if len(data) < 3 {
		return "", 0, fmt.Errorf("data too short to decode string: %w", io.ErrUnexpectedEOF)
	}

	if Tag(data[0]) != String {
		return "", 0, fmt.Errorf("expected string tag, got 0x%02x: %w", Tag(data[0]), ErrInvalidType)
	}

	offset, length := decodeLength(data[1:])
	offset += 1 // tag

	return string(data[offset : uint64(offset)+length]), offset + int(length), nil
}

func encodeSlice(arr reflect.Value) ([]byte, error) {
	arrData := make([]byte, 0)
	arrData = append(arrData, byte(Array))

	elemsData := make([]byte, 0)

	for i := 0; i < arr.Len(); i++ {
		elemData, err := Marshal(arr.Index(i).Interface())
		if err != nil {
			return nil, err
		}

		elemsData = append(elemsData, elemData...)
	}

	arrData = append(arrData, encodeLength(uint64(len(elemsData)))...)
	arrData = append(arrData, elemsData...)

	return arrData, nil
}

func decodeSlice(data []byte, typ reflect.Type) (reflect.Value, int, error) {
	arr := reflect.MakeSlice(typ, 0, 0)

	if len(data) < 2 {
		return reflect.Zero(typ), 0, fmt.Errorf("data too short to decode array: %w", io.ErrUnexpectedEOF)
	}

	if Tag(data[0]) != Array {
		return reflect.Zero(typ), 0, fmt.Errorf("expected array tag, got 0x%02x: %w", Tag(data[0]), ErrInvalidType)
	}

	offset, length := decodeLength(data[1:])
	offset += 1 // tag

	end := offset + int(length)
	for offset != end {
		elem := reflect.New(typ.Elem())
		n, err := unmarshal(data[offset:], elem.Interface())
		if err != nil {
			return reflect.Zero(typ), 0, err
		}

		arr = reflect.Append(arr, elem.Elem())

		offset += n
	}

	return arr, end, nil
}

func encodeObject(obj reflect.Value) ([]byte, error) {
	objData := make([]byte, 0)
	objData = append(objData, byte(Object))

	entriesData := make([]byte, 0)
	order := obj.MapKeys()
	sort.Slice(order, func(i, j int) bool {
		return order[i].String() < order[j].String()
	})

	for _, key := range order {
		keyData, err := Marshal(key.Interface())
		if err != nil {
			return nil, err
		}

		elemData, err := Marshal(obj.MapIndex(key).Interface())
		if err != nil {
			return nil, err
		}

		entriesData = append(entriesData, byte(Array))
		entriesData = append(entriesData, encodeLength(uint64(len(keyData)+len(elemData)))...)

		entriesData = append(entriesData, keyData...)
		entriesData = append(entriesData, elemData...)
	}

	objData = append(objData, encodeLength(uint64(len(entriesData)))...)
	objData = append(objData, entriesData...)

	return objData, nil
}

func decodeObject(data []byte, typ reflect.Type) (reflect.Value, int, error) {
	if len(data) < 2 {
		return reflect.Zero(typ), 0, fmt.Errorf("data too short to decode object: %w", io.ErrUnexpectedEOF)
	}

	switch Tag(data[0]) {
	case Object:
		obj := reflect.MakeMap(typ)

		offset, length := decodeLength(data[1:])
		offset += 1 // tag

		end := offset + int(length)
		for offset != end {
			key := reflect.New(typ.Key())
			elem := reflect.New(typ.Elem())

			entryOffset, entryLength := decodeLength(data[offset+1:])
			entryOffset += offset + 1

			keyOffset, err := unmarshal(data[entryOffset:], key.Interface())
			if err != nil {
				return reflect.Zero(typ), 0, fmt.Errorf("could not decode object key: %w", err)
			}

			_, err = unmarshal(data[entryOffset+keyOffset:], elem.Interface())
			if err != nil {
				return reflect.Zero(typ), 0, fmt.Errorf("could not decode object value: %w", err)
			}

			obj.SetMapIndex(key.Elem(), elem.Elem())

			offset = entryOffset + int(entryLength)
		}

		return obj, end, nil
	case ApplicationObject:
		obj := reflect.MakeMap(typ)

		offset, _ := decodeLength(data[1:])
		offset += 1 // tag

		offset += 3 // version?
		subOffset, length := decodeLength(data[offset+1:])
		offset += subOffset + 1

		end := offset + int(length)

		for offset != end {
			key := reflect.New(typ.Key())
			elem := reflect.New(typ.Elem())

			entryOffset, entryLength := decodeLength(data[offset+1:])
			entryOffset += offset + 1

			keyOffset, err := unmarshal(data[entryOffset:], key.Interface())
			if err != nil {
				return reflect.Zero(typ), 0, fmt.Errorf("could not decode object key: %w", err)
			}

			_, err = unmarshal(data[entryOffset+keyOffset:], elem.Interface())
			if err != nil {
				return reflect.Zero(typ), 0, fmt.Errorf("could not decode object value: %w", err)
			}

			obj.SetMapIndex(key.Elem(), elem.Elem())

			offset = entryOffset + int(entryLength)
		}
		return obj, end, nil

	default:
		return reflect.Zero(typ), 0, fmt.Errorf("expected object tag, got 0x%02x: %w", Tag(data[0]), ErrInvalidType)
	}
}

func Unmarshal(data []byte, v interface{}) error {
	_, err := unmarshal(data, v)
	return err
}

func unmarshal(data []byte, v interface{}) (int, error) {
	value := reflect.ValueOf(v)
	if value.Type().Kind() != reflect.Ptr {
		return 0, fmt.Errorf("invalid type %v: %w", value.Type(), ErrInvalidType)
	}

	switch value.Type().Elem().Kind() {
	case reflect.Bool:
		ret, n, err := decodeBool(data)
		if err != nil {
			return 0, fmt.Errorf("could not decode bool: %w", err)
		}

		reflect.Indirect(value).Set(reflect.ValueOf(ret))
		return n, nil
	case reflect.Uint8, reflect.Int8,
		reflect.Uint16, reflect.Int16,
		reflect.Uint32, reflect.Int32,
		reflect.Uint64, reflect.Int64,
		reflect.Uint, reflect.Int:
		ret, n, err := decodeInt(data)
		if err != nil {
			return 0, fmt.Errorf("could not decode int: %w", err)
		}

		reflect.Indirect(value).Set(reflect.ValueOf(ret).Convert(value.Type().Elem()))
		return n, nil

	case reflect.String:
		ret, n, err := decodeString(data)
		if err != nil {
			return 0, fmt.Errorf("could not decode string: %w", err)
		}

		reflect.Indirect(value).Set(reflect.ValueOf(ret))
		return n, nil
	case reflect.Slice:
		ret, n, err := decodeSlice(data, value.Type().Elem())
		if err != nil {
			return 0, fmt.Errorf("could not decode array: %w", err)
		}

		reflect.Indirect(value).Set(ret)
		return n, nil
	case reflect.Map:
		ret, n, err := decodeObject(data, value.Type().Elem())
		if err != nil {
			return 0, fmt.Errorf("could not decode object: %w", err)
		}

		reflect.Indirect(value).Set(ret)
		return n, nil
	case reflect.Interface:
		switch Tag(data[0]) {
		case Bool:
			ret, n, err := decodeBool(data)
			if err != nil {
				return 0, err
			}

			reflect.Indirect(value).Set(reflect.ValueOf(ret))
			return n, nil
		case Int:
			ret, n, err := decodeInt(data)
			if err != nil {
				return 0, err
			}

			reflect.Indirect(value).Set(reflect.ValueOf(ret))
			return n, nil
		case String:
			ret, n, err := decodeString(data)
			if err != nil {
				return 0, fmt.Errorf("could not decode string: %w", err)
			}

			reflect.Indirect(value).Set(reflect.ValueOf(ret))
			return n, nil
		case Array:
			ret, n, err := decodeSlice(data, reflect.TypeOf([]interface{}{}))
			if err != nil {
				return 0, fmt.Errorf("could not decode array: %w", err)
			}

			reflect.Indirect(value).Set(ret)
			return n, nil
		case Object:
			ret, n, err := decodeObject(data, reflect.TypeOf(map[string]interface{}{}))
			if err != nil {
				return 0, fmt.Errorf("could not decode object: %w", err)
			}

			reflect.Indirect(value).Set(ret)
			return n, nil
		}
	}

	return 0, fmt.Errorf("unimpl unmarshal")
}

func Marshal(v interface{}) ([]byte, error) {
	value := reflect.ValueOf(v)
	switch value.Type().Kind() {
	case reflect.Bool:
		return encodeBool(value.Bool()), nil
	case reflect.Uint8, reflect.Int8,
		reflect.Uint16, reflect.Int16,
		reflect.Uint32, reflect.Int32,
		reflect.Uint64, reflect.Int64,
		reflect.Uint, reflect.Int:
		return encodeInt(value.Convert(reflect.TypeOf(int64(0))).Int(), uint64(value.Type().Size())), nil
	case reflect.String:
		return encodeString(value.String()), nil
	case reflect.Slice:
		return encodeSlice(value)
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("maps must have string-like keys: %w", ErrInvalidType)
		}
		return encodeObject(value)
	}

	return nil, fmt.Errorf("unimpl marshal")
}
