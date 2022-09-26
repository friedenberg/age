package age

import (
	"io"
	"sync"

	"filippo.io/age/internal/stream"
)

var instancePool *pool

func init() {
	instancePool = newPool()
}

type pool struct {
	reader *sync.Pool
	writer *sync.Pool
}

func newPool() *pool {
	return &pool{
		reader: &sync.Pool{
			New: func() interface{} {
				return &stream.Reader{}
			},
		},
		writer: &sync.Pool{
			New: func() interface{} {
				return &stream.Writer{}
			},
		},
	}
}

func (p *pool) GetReader(key []byte, src io.Reader) (r *stream.Reader, err error) {
	r = p.reader.Get().(*stream.Reader)

	if err = r.Reset(key, src); err != nil {
		return
	}

	return
}

func (p *pool) GetWriter(key []byte, dst io.Writer) (w *stream.Writer, err error) {
	w = p.writer.Get().(*stream.Writer)

	if err = w.Reset(key, dst); err != nil {
		return
	}

	return
}

func PutWriter(w *stream.Writer) {
	instancePool.writer.Put(w)
}

func PutReader(r *stream.Reader) {
	instancePool.reader.Put(r)
}
