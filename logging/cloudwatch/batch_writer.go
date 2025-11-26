package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// BatchWriter is an io.Writer that batch writes log events to the AWS
// CloudWatch logs API.
type BatchWriter struct {
	svc               *cloudwatchlogs.Client
	groupName         string
	streamName        string
	nextSequenceToken *string
	m                 sync.Mutex
	ch                chan *types.InputLogEvent
	flushWG           sync.WaitGroup
	err               *error
}

// NewBatchWriter creates an unbuffered BatchWriter with the given group and
// stream.
func NewBatchWriter(groupName, streamName string, cfg aws.Config) (*BatchWriter, error) {
	return NewBatchWriterWithDuration(groupName, streamName, cfg, 0)
}

func (h *BatchWriter) getOrCreateCloudWatchLogGroup() (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
	resp, err := h.svc.DescribeLogStreams(context.TODO(), &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName:        aws.String(h.groupName),
		LogStreamNamePrefix: aws.String(h.streamName),
	})

	if err != nil {
		var notFoundErr *types.ResourceNotFoundException
		if ok := errors.As(err, &notFoundErr); ok {
			_, err = h.svc.CreateLogGroup(context.TODO(), &cloudwatchlogs.CreateLogGroupInput{
				LogGroupName: aws.String(h.groupName),
			})
			if err != nil {
				return nil, err
			}
			return h.getOrCreateCloudWatchLogGroup()
		}
		return nil, err
	}
	return resp, nil

}

// NewBatchWriterWithDuration creates a BatchWriter with the given group and
// stream. To create an unbuffered writer, set batchFrequency to 0.
func NewBatchWriterWithDuration(groupName, streamName string, cfg aws.Config, batchFrequency time.Duration) (*BatchWriter, error) {
	w := &BatchWriter{
		svc:        cloudwatchlogs.NewFromConfig(cfg),
		groupName:  groupName,
		streamName: streamName,
	}

	resp, err := w.getOrCreateCloudWatchLogGroup()
	if err != nil {
		return nil, err
	}

	if batchFrequency > 0 {
		w.ch = make(chan *types.InputLogEvent, 10000)
		ticker := time.NewTicker(batchFrequency)

		go w.putBatches(ticker.C)
	}

	// grab the next sequence token
	if len(resp.LogStreams) > 0 {
		w.nextSequenceToken = resp.LogStreams[0].UploadSequenceToken
		return w, nil
	}

	// create stream if it doesn't exist. the next sequence token will be null
	_, err = w.svc.CreateLogStream(context.TODO(), &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(groupName),
		LogStreamName: aws.String(streamName),
	})
	if err != nil {
		return nil, err
	}

	return w, nil
}

// Force flushing of currently stored messages
func (w *BatchWriter) Flush() error {
	w.flushWG.Add(1)
	w.ch <- nil
	w.flushWG.Wait()
	if w.err != nil {
		return *w.err
	}
	return nil
}

func (w *BatchWriter) putBatches(ticker <-chan time.Time) {
	var batch []types.InputLogEvent
	size := 0
	for {
		select {
		case p := <-w.ch:
			if p != nil {
				messageSize := len(*p.Message) + 26
				if size+messageSize >= 1048576 || len(batch) == 10000 {
					w.sendBatch(batch)
					batch = nil
					size = 0
				}
				batch = append(batch, *p)
				size += messageSize
			} else {
				// Flush event (nil)
				w.sendBatch(batch)
				w.flushWG.Done()
				batch = nil
				size = 0
			}
		case <-ticker:
			w.sendBatch(batch)
			batch = nil
			size = 0
		}
	}
}

func (w *BatchWriter) sendBatch(batch []types.InputLogEvent) {
	if len(batch) == 0 {
		return
	}
	params := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     batch,
		LogGroupName:  aws.String(w.groupName),
		LogStreamName: aws.String(w.streamName),
		SequenceToken: w.nextSequenceToken,
	}
	resp, err := w.svc.PutLogEvents(context.TODO(), params)
	if err == nil {
		w.nextSequenceToken = resp.NextSequenceToken
		return
	}

	w.err = &err
	var invalidSeqTokenErr *types.InvalidSequenceTokenException
	if ok := errors.As(err, &invalidSeqTokenErr); ok {
		w.nextSequenceToken = invalidSeqTokenErr.ExpectedSequenceToken
		w.sendBatch(batch)
		return
	}
}

func (w *BatchWriter) Write(p []byte) (n int, err error) {
	event := &types.InputLogEvent{
		Message:   aws.String(string(p)),
		Timestamp: aws.Int64(int64(time.Nanosecond) * time.Now().UnixNano() / int64(time.Millisecond)),
	}

	if w.ch != nil {
		w.ch <- event
		if w.err != nil {
			lastErr := w.err
			w.err = nil
			return 0, fmt.Errorf("%v", *lastErr)
		}
		return len(p), nil
	}

	w.m.Lock()
	defer w.m.Unlock()

	params := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     []types.InputLogEvent{*event},
		LogGroupName:  aws.String(w.groupName),
		LogStreamName: aws.String(w.streamName),
		SequenceToken: w.nextSequenceToken,
	}
	resp, err := w.svc.PutLogEvents(context.TODO(), params)
	if err != nil {
		return 0, err
	}

	w.nextSequenceToken = resp.NextSequenceToken

	return len(p), nil
}
