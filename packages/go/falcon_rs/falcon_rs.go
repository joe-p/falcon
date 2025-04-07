
package falcon_rs

// #include <falcon_rs.h>
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"unsafe"
	"encoding/binary"
	"math"
)



// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer {
		inner: C.RustBuffer {
			capacity: C.uint64_t(b.Capacity()),
			len: C.uint64_t(b.Len()),
			data: (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func( status *C.RustCallStatus) bool {
		C.ffi_falcon_rs_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}


func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes {
		len: C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}
	
	return rustCall(func( status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_falcon_rs_rustbuffer_from_bytes(foreign, status)
	})
}


type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}



func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer { inner: status.errorBuf })
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer { inner: status.errorBuf })))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer {
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}


func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}


func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {
        
        uniffiCheckChecksums()
}


func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 26
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_falcon_rs_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("falcon_rs: UniFFI contract version mismatch")
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_falcon_rs_checksum_func_generate_key()
	})
	if checksum != 26145 {
		// If this happens try cleaning and rebuilding your project
		panic("falcon_rs: uniffi_falcon_rs_checksum_func_generate_key: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_falcon_rs_checksum_func_sign_compressed()
	})
	if checksum != 63369 {
		// If this happens try cleaning and rebuilding your project
		panic("falcon_rs: uniffi_falcon_rs_checksum_func_sign_compressed: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_falcon_rs_checksum_func_verify()
	})
	if checksum != 25565 {
		// If this happens try cleaning and rebuilding your project
		panic("falcon_rs: uniffi_falcon_rs_checksum_func_verify: UniFFI API checksum mismatch")
	}
	}
}




type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct {}

func (FfiDestroyerInt32) Destroy(_ int32) {}


type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct {}

func (FfiDestroyerString) Destroy(_ string) {}


type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct {}

func (FfiDestroyerBytes) Destroy(_ []byte) {}



type KeyPair struct {
	PublicKey []byte
	PrivateKey []byte
}

func (r *KeyPair) Destroy() {
		FfiDestroyerBytes{}.Destroy(r.PublicKey);
		FfiDestroyerBytes{}.Destroy(r.PrivateKey);
}

type FfiConverterKeyPair struct {}

var FfiConverterKeyPairINSTANCE = FfiConverterKeyPair{}

func (c FfiConverterKeyPair) Lift(rb RustBufferI) KeyPair {
	return LiftFromRustBuffer[KeyPair](c, rb)
}

func (c FfiConverterKeyPair) Read(reader io.Reader) KeyPair {
	return KeyPair {
			FfiConverterBytesINSTANCE.Read(reader),
			FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterKeyPair) Lower(value KeyPair) C.RustBuffer {
	return LowerIntoRustBuffer[KeyPair](c, value)
}

func (c FfiConverterKeyPair) Write(writer io.Writer, value KeyPair) {
		FfiConverterBytesINSTANCE.Write(writer, value.PublicKey);
		FfiConverterBytesINSTANCE.Write(writer, value.PrivateKey);
}

type FfiDestroyerKeyPair struct {}

func (_ FfiDestroyerKeyPair) Destroy(value KeyPair) {
	value.Destroy()
}

type Error struct {
	err error
}

// Convience method to turn *Error into error
// Avoiding treating nil pointer as non nil error interface
func (err *Error) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err Error) Error() string {
	return fmt.Sprintf("Error: %s", err.err.Error())
}

func (err Error) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrErrorKeygenFail = fmt.Errorf("ErrorKeygenFail")
var ErrErrorSignFail = fmt.Errorf("ErrorSignFail")
var ErrErrorVerifyFail = fmt.Errorf("ErrorVerifyFail")
var ErrErrorConvertFail = fmt.Errorf("ErrorConvertFail")

// Variant structs
type ErrorKeygenFail struct {
	Field0 int32
}
func NewErrorKeygenFail(
	var0 int32,
) *Error {
	return &Error { err: &ErrorKeygenFail {
			Field0: var0,} }
}

func (e ErrorKeygenFail) destroy() {
		FfiDestroyerInt32{}.Destroy(e.Field0)
}


func (err ErrorKeygenFail) Error() string {
	return fmt.Sprint("KeygenFail",
		": ",
		
		"Field0=",
		err.Field0,
	)
}

func (self ErrorKeygenFail) Is(target error) bool {
	return target == ErrErrorKeygenFail
}
type ErrorSignFail struct {
	Field0 int32
}
func NewErrorSignFail(
	var0 int32,
) *Error {
	return &Error { err: &ErrorSignFail {
			Field0: var0,} }
}

func (e ErrorSignFail) destroy() {
		FfiDestroyerInt32{}.Destroy(e.Field0)
}


func (err ErrorSignFail) Error() string {
	return fmt.Sprint("SignFail",
		": ",
		
		"Field0=",
		err.Field0,
	)
}

func (self ErrorSignFail) Is(target error) bool {
	return target == ErrErrorSignFail
}
type ErrorVerifyFail struct {
	Field0 int32
}
func NewErrorVerifyFail(
	var0 int32,
) *Error {
	return &Error { err: &ErrorVerifyFail {
			Field0: var0,} }
}

func (e ErrorVerifyFail) destroy() {
		FfiDestroyerInt32{}.Destroy(e.Field0)
}


func (err ErrorVerifyFail) Error() string {
	return fmt.Sprint("VerifyFail",
		": ",
		
		"Field0=",
		err.Field0,
	)
}

func (self ErrorVerifyFail) Is(target error) bool {
	return target == ErrErrorVerifyFail
}
type ErrorConvertFail struct {
	Field0 int32
}
func NewErrorConvertFail(
	var0 int32,
) *Error {
	return &Error { err: &ErrorConvertFail {
			Field0: var0,} }
}

func (e ErrorConvertFail) destroy() {
		FfiDestroyerInt32{}.Destroy(e.Field0)
}


func (err ErrorConvertFail) Error() string {
	return fmt.Sprint("ConvertFail",
		": ",
		
		"Field0=",
		err.Field0,
	)
}

func (self ErrorConvertFail) Is(target error) bool {
	return target == ErrErrorConvertFail
}

type FfiConverterError struct{}

var FfiConverterErrorINSTANCE = FfiConverterError{}

func (c FfiConverterError) Lift(eb RustBufferI) *Error {
	return LiftFromRustBuffer[*Error](c, eb)
}

func (c FfiConverterError) Lower(value *Error) C.RustBuffer {
	return LowerIntoRustBuffer[*Error](c, value)
}

func (c FfiConverterError) Read(reader io.Reader) *Error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &Error{ &ErrorKeygenFail{
			Field0: FfiConverterInt32INSTANCE.Read(reader),
		}}
	case 2:
		return &Error{ &ErrorSignFail{
			Field0: FfiConverterInt32INSTANCE.Read(reader),
		}}
	case 3:
		return &Error{ &ErrorVerifyFail{
			Field0: FfiConverterInt32INSTANCE.Read(reader),
		}}
	case 4:
		return &Error{ &ErrorConvertFail{
			Field0: FfiConverterInt32INSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterError.Read()", errorID))
	}
}

func (c FfiConverterError) Write(writer io.Writer, value *Error) {
	switch variantValue := value.err.(type) {
		case *ErrorKeygenFail:
			writeInt32(writer, 1)
			FfiConverterInt32INSTANCE.Write(writer, variantValue.Field0)
		case *ErrorSignFail:
			writeInt32(writer, 2)
			FfiConverterInt32INSTANCE.Write(writer, variantValue.Field0)
		case *ErrorVerifyFail:
			writeInt32(writer, 3)
			FfiConverterInt32INSTANCE.Write(writer, variantValue.Field0)
		case *ErrorConvertFail:
			writeInt32(writer, 4)
			FfiConverterInt32INSTANCE.Write(writer, variantValue.Field0)
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiConverterError.Write", value))
	}
}

type FfiDestroyerError struct {}

func (_ FfiDestroyerError) Destroy(value *Error) {
	switch variantValue := value.err.(type) {
		case ErrorKeygenFail:
			variantValue.destroy()
		case ErrorSignFail:
			variantValue.destroy()
		case ErrorVerifyFail:
			variantValue.destroy()
		case ErrorConvertFail:
			variantValue.destroy()
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerError.Destroy", value))
	}
}


func GenerateKey(seed []byte) (KeyPair, *Error) {
	_uniffiRV, _uniffiErr := rustCallWithError[Error](FfiConverterError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_falcon_rs_fn_func_generate_key(FfiConverterBytesINSTANCE.Lower(seed),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue KeyPair
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterKeyPairINSTANCE.Lift(_uniffiRV), _uniffiErr
		}
}

func SignCompressed(privateKeySlice []byte, msg []byte) ([]byte, *Error) {
	_uniffiRV, _uniffiErr := rustCallWithError[Error](FfiConverterError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_falcon_rs_fn_func_sign_compressed(FfiConverterBytesINSTANCE.Lower(privateKeySlice), FfiConverterBytesINSTANCE.Lower(msg),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []byte
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterBytesINSTANCE.Lift(_uniffiRV), _uniffiErr
		}
}

func Verify(publicKeySlice []byte, signature []byte, msg []byte) *Error {
	_, _uniffiErr := rustCallWithError[Error](FfiConverterError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_falcon_rs_fn_func_verify(FfiConverterBytesINSTANCE.Lower(publicKeySlice), FfiConverterBytesINSTANCE.Lower(signature), FfiConverterBytesINSTANCE.Lower(msg),_uniffiStatus)
		return false
	})
		return _uniffiErr
}

