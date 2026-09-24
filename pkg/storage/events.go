package storage

// EventSink receives telemetry events. *api.WSHub implements it via Broadcast
type EventSink interface {
	Broadcast(e LogEvent)
}
