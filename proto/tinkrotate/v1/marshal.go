package tinkrotatev1

import "google.golang.org/protobuf/encoding/protojson"

func (m *KeyMetadata) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(m)
}

func (m *KeyMetadata) UnmarshalJSON(data []byte) error {
	return protojson.Unmarshal(data, m)
}
