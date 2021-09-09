package tcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var ErrServerClosed = errors.New("tcp: server closed")

var L *zap.Logger = zap.NewNop()

type IProtocol interface {
	GetHeaderSize() int
	NewHeader([]byte) (IHeader, error)
	Decrypt([]byte, uint8) ([]byte, bool)
}

type IHeader interface {
	GetCmd() uint16
	GetCode() uint8
	GetBodySize() int
}

type IWorker interface {
	GetConn() net.Conn
	OnBeforeHandle(ctx context.Context, cmd uint16, body []byte) error
	OnAfterHandle(ctx context.Context, cmd uint16, err error)
	Close()
}

type Server struct {
	ln           net.Listener
	readTimeout  time.Duration
	writeTimeout time.Duration

	mu         sync.RWMutex
	activeConn map[net.Conn]IWorker
	doneChan   chan struct{}
	isShutdown int32

	protocol IProtocol
	workerFn func(net.Conn) IWorker
}

func NewServer(protocol IProtocol, workerFn func(net.Conn) IWorker, options ...OptionFn) *Server {
	s := &Server{
		activeConn: make(map[net.Conn]IWorker),
		doneChan:   make(chan struct{}, 1),
		protocol:   protocol,
		workerFn:   workerFn,
	}

	for _, v := range options {
		v(s)
	}

	return s
}

func (s *Server) Address() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *Server) ActiveClientConn() []net.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sl := make([]net.Conn, 0, len(s.activeConn))
	for k := range s.activeConn {
		sl = append(sl, k)
	}
	return sl
}

func (s *Server) Serve(address string) error {
	L.Sugar().Info("server pid:", os.Getpid())
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	return s.serveListener(ln)
}

func (s *Server) serveListener(ln net.Listener) error {
	var tempDelay time.Duration

	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.doneChan:
				return ErrServerClosed
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				L.Sugar().Warnf("accept error %v retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			if strings.Contains(err.Error(), "listener closed") {
				return ErrServerClosed
			}

			return err
		}
		tempDelay = 0

		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			ss := runtime.Stack(buf, false)
			if ss > size {
				ss = size
			}
			buf = buf[:ss]

			L.Sugar().Errorf("conn %s panic error: %s stack:\n %s", conn.RemoteAddr(), err, buf)
		}

		s.closeConn(conn)
	}()

	if isShutdown(s) {
		return
	}

	worker := s.workerFn(conn)
	s.mu.Lock()
	s.activeConn[conn] = worker
	s.mu.Unlock()

	for {
		if isShutdown(s) {
			s.closeConn(conn)
			return
		}

		now := time.Now()
		if s.readTimeout != 0 {
			conn.SetReadDeadline(now.Add(s.readTimeout))
		}
		if s.writeTimeout != 0 {
			conn.SetWriteDeadline(now.Add(s.writeTimeout))
		}

		// receive package
		var hb = make([]byte, s.protocol.GetHeaderSize())
		_, err := io.ReadFull(conn, hb)
		if err != nil {
			return
		}

		header, err := s.protocol.NewHeader(hb)
		if err != nil {
			L.Sugar().Errorf("new header with %v failed %s", hb, err)
			return
		}

		body := make([]byte, header.GetBodySize())
		_, err = io.ReadFull(conn, body)
		if err != nil {
			L.Sugar().Warnf("read body failed %s", err)
			return
		}

		body, ok := s.protocol.Decrypt(body, header.GetCode())
		if !ok {
			L.Sugar().Error("decrypt failed")
			return
		}

		ctx := context.Background()
		worker.OnBeforeHandle(ctx, header.GetCmd(), body)
		s.proc(ctx, worker, header.GetCmd(), body)
	}
}

func (s *Server) proc(ctx context.Context, worker IWorker, cmd uint16, body []byte) {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			ss := runtime.Stack(buf, false)
			if ss > size {
				ss = size
			}
			buf = buf[:ss]

			L.Sugar().Errorf("panic error: %s stack:\n %s", err, buf)
		}
	}()

	method := fmt.Sprintf("On0x%X", cmd)
	v := reflect.ValueOf(worker).MethodByName(method)
	if !v.IsValid() {
		L.Sugar().Warnf("method %s not found", method)
		return
	}

	L.Sugar().Debugf("call %s body len %d", method, len(body))

	res := v.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(body)})
	if len(res) > 0 {
		var err error
		v := res[0].Interface()
		if e, ok := v.(error); ok {
			err = e
		}
		worker.OnAfterHandle(ctx, cmd, err)
		return
	}

	panic("invalid method")
}

func isShutdown(s *Server) bool {
	return atomic.LoadInt32(&s.isShutdown) == 1
}

func (s *Server) closeConn(conn net.Conn) {
	s.mu.Lock()
	s.activeConn[conn].Close()
	delete(s.activeConn, conn)
	s.mu.Unlock()
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}

	for conn, worker := range s.activeConn {
		worker.Close()
		delete(s.activeConn, conn)
	}
	s.closeDoneChanLocked()
	return err
}

func (s *Server) closeDoneChanLocked() {
	select {
	case <-s.doneChan:
	default:
		close(s.doneChan)
	}
}

type OptionFn func(*Server)

func WithReadTimeout(readTimeout time.Duration) OptionFn {
	return func(s *Server) {
		s.readTimeout = readTimeout
	}
}

func WithWriteTimeout(writeTimeout time.Duration) OptionFn {
	return func(s *Server) {
		s.writeTimeout = writeTimeout
	}
}
