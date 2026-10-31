package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrInvalidEvent      = errors.New("invalid audit event")
	ErrDuplicateConflict = errors.New("audit event ID already used for different data")
)

type Service struct{ db *gorm.DB }

func NewService(db *gorm.DB) *Service { return &Service{db: db} }

func RecordSecurity(db *gorm.DB, event SecurityEvent) error {
	if !validField(event.Type, 64) || !validField(event.Result, 64) || (event.VisibleToUser && (event.UserID == nil || *event.UserID == uuid.Nil)) {
		return ErrInvalidEvent
	}
	event.ID = uuid.New()
	event.OccurredAt = time.Now().UTC()
	return db.Create(&event).Error
}

type securityCursor struct {
	Time time.Time `json:"t"`
	ID   uuid.UUID `json:"i"`
}

type SecurityPage struct {
	Events     []SecurityEvent `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

func (s *Service) ListSecurity(ctx context.Context, userID uuid.UUID, limit int, after string) (*SecurityPage, error) {
	if userID == uuid.Nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidEvent
	}
	query := s.db.WithContext(ctx).Where("user_id = ? AND visible_to_user = ?", userID, true)
	if after != "" {
		data, err := base64.RawURLEncoding.DecodeString(after)
		var position securityCursor
		if err != nil || len(data) > 512 || json.Unmarshal(data, &position) != nil || position.Time.IsZero() || position.ID == uuid.Nil {
			return nil, ErrInvalidEvent
		}
		query = query.Where("(occurred_at < ? OR (occurred_at = ? AND id < ?))", position.Time, position.Time, position.ID)
	}
	events := []SecurityEvent{}
	if err := query.Order("occurred_at DESC, id DESC").Limit(limit + 1).Find(&events).Error; err != nil {
		return nil, err
	}
	page := &SecurityPage{Events: events}
	if len(events) > limit {
		last := events[limit-1]
		data, err := json.Marshal(securityCursor{Time: last.OccurredAt, ID: last.ID})
		if err != nil {
			return nil, err
		}
		page.Events = events[:limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return page, nil
}

func validField(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Record binds the event to the authenticated resource, accepts identical
// retries idempotently, and rejects collisions with different event contents.
type Source struct{ ID, Identifier, Status string }

func (s *Service) Record(ctx context.Context, source Source, event Event) error {
	if source.ID == "" || source.Status != "active" || event.Resource != source.Identifier || event.Subject == uuid.Nil || !validField(event.EventID, 128) || !validField(event.ClientID, 128) || !validField(event.Action, 64) || !validField(event.DataCategory, 64) || (event.Result != "success" && event.Result != "denied" && event.Result != "error") || event.OccurredAt.IsZero() || event.OccurredAt.After(time.Now().Add(5*time.Minute)) {
		return ErrInvalidEvent
	}
	event.SourceResourceID = source.ID
	event.OccurredAt = event.OccurredAt.UTC().Truncate(time.Microsecond)
	event.ReceivedAt = time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Table("users").Where("id = ?", event.Subject).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return ErrInvalidEvent
		}
		if err := tx.Table("oauth_clients").Where("id = ?", event.ClientID).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return ErrInvalidEvent
		}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&event)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			return nil
		}
		var prior Event
		if err := tx.Where("source_resource_id = ? AND event_id = ?", event.SourceResourceID, event.EventID).First(&prior).Error; err != nil {
			return err
		}
		if prior.Subject != event.Subject || prior.ClientID != event.ClientID || prior.Resource != event.Resource || prior.Action != event.Action || prior.DataCategory != event.DataCategory || prior.Result != event.Result || !prior.OccurredAt.Equal(event.OccurredAt) {
			return ErrDuplicateConflict
		}
		return nil
	})
}

type cursor struct {
	Time   time.Time `json:"t"`
	Source string    `json:"s"`
	Event  string    `json:"e"`
}

type Page struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

func (s *Service) List(ctx context.Context, userID uuid.UUID, limit int, after string) (*Page, error) {
	if userID == uuid.Nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidEvent
	}
	query := s.db.WithContext(ctx).Where("subject = ?", userID)
	if after != "" {
		var position cursor
		data, err := base64.RawURLEncoding.DecodeString(after)
		if err != nil || len(data) > 512 || json.Unmarshal(data, &position) != nil || position.Time.IsZero() || len(position.Source) == 0 || len(position.Source) > 128 || !validField(position.Event, 128) {
			return nil, ErrInvalidEvent
		}
		query = query.Where("(occurred_at < ? OR (occurred_at = ? AND source_resource_id < ?) OR (occurred_at = ? AND source_resource_id = ? AND event_id < ?))", position.Time, position.Time, position.Source, position.Time, position.Source, position.Event)
	}
	events := []Event{}
	if err := query.Order("occurred_at DESC, source_resource_id DESC, event_id DESC").Limit(limit + 1).Find(&events).Error; err != nil {
		return nil, err
	}
	page := &Page{Events: events}
	if len(events) > limit {
		last := events[limit-1]
		data, err := json.Marshal(cursor{Time: last.OccurredAt, Source: last.SourceResourceID, Event: last.EventID})
		if err != nil {
			return nil, err
		}
		page.Events = events[:limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return page, nil
}
