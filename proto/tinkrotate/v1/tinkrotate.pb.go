// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: tinkrotate/v1/tinkrotate.proto

package tinkrotatev1

import (
	tink_go_proto "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// KeyState defines the lifecycle state of a key within the rotation policy.
type KeyState int32

const (
	KeyState_KEY_STATE_UNSPECIFIED KeyState = 0 // Default, should not be used in practice
	KeyState_KEY_STATE_PENDING     KeyState = 1 // Key generated, propagating, not yet primary
	KeyState_KEY_STATE_PRIMARY     KeyState = 2 // Active key for signing/encryption
	KeyState_KEY_STATE_PHASING_OUT KeyState = 3 // Previous primary, used only for verification/decryption
	KeyState_KEY_STATE_DISABLED    KeyState = 4 // Key is no longer used for any operation, awaiting deletion
)

// Enum value maps for KeyState.
var (
	KeyState_name = map[int32]string{
		0: "KEY_STATE_UNSPECIFIED",
		1: "KEY_STATE_PENDING",
		2: "KEY_STATE_PRIMARY",
		3: "KEY_STATE_PHASING_OUT",
		4: "KEY_STATE_DISABLED",
	}
	KeyState_value = map[string]int32{
		"KEY_STATE_UNSPECIFIED": 0,
		"KEY_STATE_PENDING":     1,
		"KEY_STATE_PRIMARY":     2,
		"KEY_STATE_PHASING_OUT": 3,
		"KEY_STATE_DISABLED":    4,
	}
)

func (x KeyState) Enum() *KeyState {
	p := new(KeyState)
	*p = x
	return p
}

func (x KeyState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyState) Descriptor() protoreflect.EnumDescriptor {
	return file_tinkrotate_v1_tinkrotate_proto_enumTypes[0].Descriptor()
}

func (KeyState) Type() protoreflect.EnumType {
	return &file_tinkrotate_v1_tinkrotate_proto_enumTypes[0]
}

func (x KeyState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyState.Descriptor instead.
func (KeyState) EnumDescriptor() ([]byte, []int) {
	return file_tinkrotate_v1_tinkrotate_proto_rawDescGZIP(), []int{0}
}

// RotationPolicy defines the parameters for automated key rotation for a specific keyset.
type RotationPolicy struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The specific key template to use when generating new keys for this keyset.
	// This field MUST be set.
	KeyTemplate *tink_go_proto.KeyTemplate `protobuf:"bytes,1,opt,name=key_template,json=keyTemplate,proto3" json:"key_template,omitempty"`
	// Duration a key stays PRIMARY before rotation is initiated. MUST be positive.
	PrimaryDuration *durationpb.Duration `protobuf:"bytes,2,opt,name=primary_duration,json=primaryDuration,proto3" json:"primary_duration,omitempty"`
	// Minimum time a PENDING key must exist before it's eligible for PRIMARY promotion.
	// MUST be non-negative and <= primary_duration.
	PropagationTime *durationpb.Duration `protobuf:"bytes,3,opt,name=propagation_time,json=propagationTime,proto3" json:"propagation_time,omitempty"`
	// Duration a key stays PHASING_OUT (after being primary) before being DISABLED.
	// MUST be non-negative.
	PhaseOutDuration *durationpb.Duration `protobuf:"bytes,4,opt,name=phase_out_duration,json=phaseOutDuration,proto3" json:"phase_out_duration,omitempty"`
	// Duration a key stays DISABLED before being marked for deletion (DESTROYED).
	// MUST be non-negative.
	DeletionGracePeriod *durationpb.Duration `protobuf:"bytes,5,opt,name=deletion_grace_period,json=deletionGracePeriod,proto3" json:"deletion_grace_period,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *RotationPolicy) Reset() {
	*x = RotationPolicy{}
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotationPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotationPolicy) ProtoMessage() {}

func (x *RotationPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotationPolicy.ProtoReflect.Descriptor instead.
func (*RotationPolicy) Descriptor() ([]byte, []int) {
	return file_tinkrotate_v1_tinkrotate_proto_rawDescGZIP(), []int{0}
}

func (x *RotationPolicy) GetKeyTemplate() *tink_go_proto.KeyTemplate {
	if x != nil {
		return x.KeyTemplate
	}
	return nil
}

func (x *RotationPolicy) GetPrimaryDuration() *durationpb.Duration {
	if x != nil {
		return x.PrimaryDuration
	}
	return nil
}

func (x *RotationPolicy) GetPropagationTime() *durationpb.Duration {
	if x != nil {
		return x.PropagationTime
	}
	return nil
}

func (x *RotationPolicy) GetPhaseOutDuration() *durationpb.Duration {
	if x != nil {
		return x.PhaseOutDuration
	}
	return nil
}

func (x *RotationPolicy) GetDeletionGracePeriod() *durationpb.Duration {
	if x != nil {
		return x.DeletionGracePeriod
	}
	return nil
}

// KeyMetadata stores rotation-specific information for a single key within a Tink Keyset.
type KeyMetadata struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The Tink Key ID this metadata corresponds to.
	KeyId uint32 `protobuf:"varint,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// The state of the key in its rotation lifecycle.
	State KeyState `protobuf:"varint,2,opt,name=state,proto3,enum=lstoll.tinkrotate.v1.KeyState" json:"state,omitempty"`
	// When the key was initially generated and added to the keyset (as PENDING).
	CreationTime *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=creation_time,json=creationTime,proto3" json:"creation_time,omitempty"`
	// When the key was promoted to PRIMARY status. Reset if demoted.
	PromotionTime *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=promotion_time,json=promotionTime,proto3" json:"promotion_time,omitempty"` // Optional: only set when state is PRIMARY
	// When the key was moved to DISABLED status.
	DisableTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=disable_time,json=disableTime,proto3" json:"disable_time,omitempty"` // Optional: only set when state is DISABLED or later
	// When the key is scheduled to be permanently deleted (destroyed) from the keyset.
	DeletionTime  *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=deletion_time,json=deletionTime,proto3" json:"deletion_time,omitempty"` // Optional: only set when state is DISABLED
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *KeyMetadata) Reset() {
	*x = KeyMetadata{}
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KeyMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMetadata) ProtoMessage() {}

func (x *KeyMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyMetadata.ProtoReflect.Descriptor instead.
func (*KeyMetadata) Descriptor() ([]byte, []int) {
	return file_tinkrotate_v1_tinkrotate_proto_rawDescGZIP(), []int{1}
}

func (x *KeyMetadata) GetKeyId() uint32 {
	if x != nil {
		return x.KeyId
	}
	return 0
}

func (x *KeyMetadata) GetState() KeyState {
	if x != nil {
		return x.State
	}
	return KeyState_KEY_STATE_UNSPECIFIED
}

func (x *KeyMetadata) GetCreationTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreationTime
	}
	return nil
}

func (x *KeyMetadata) GetPromotionTime() *timestamppb.Timestamp {
	if x != nil {
		return x.PromotionTime
	}
	return nil
}

func (x *KeyMetadata) GetDisableTime() *timestamppb.Timestamp {
	if x != nil {
		return x.DisableTime
	}
	return nil
}

func (x *KeyMetadata) GetDeletionTime() *timestamppb.Timestamp {
	if x != nil {
		return x.DeletionTime
	}
	return nil
}

// KeyRotationMetadata encapsulates metadata for all keys in a managed keyset.
type KeyRotationMetadata struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The rotation policy governing this specific keyset.
	// This field MUST be set for the AutoRotator to manage this keyset.
	RotationPolicy *RotationPolicy `protobuf:"bytes,1,opt,name=rotation_policy,json=rotationPolicy,proto3" json:"rotation_policy,omitempty"`
	// Metadata for each individual key within the keyset, keyed by Key ID.
	KeyMetadata   map[uint32]*KeyMetadata `protobuf:"bytes,2,rep,name=key_metadata,json=keyMetadata,proto3" json:"key_metadata,omitempty" protobuf_key:"varint,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *KeyRotationMetadata) Reset() {
	*x = KeyRotationMetadata{}
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KeyRotationMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyRotationMetadata) ProtoMessage() {}

func (x *KeyRotationMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_tinkrotate_v1_tinkrotate_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyRotationMetadata.ProtoReflect.Descriptor instead.
func (*KeyRotationMetadata) Descriptor() ([]byte, []int) {
	return file_tinkrotate_v1_tinkrotate_proto_rawDescGZIP(), []int{2}
}

func (x *KeyRotationMetadata) GetRotationPolicy() *RotationPolicy {
	if x != nil {
		return x.RotationPolicy
	}
	return nil
}

func (x *KeyRotationMetadata) GetKeyMetadata() map[uint32]*KeyMetadata {
	if x != nil {
		return x.KeyMetadata
	}
	return nil
}

var File_tinkrotate_v1_tinkrotate_proto protoreflect.FileDescriptor

const file_tinkrotate_v1_tinkrotate_proto_rawDesc = "" +
	"\n" +
	"\x1etinkrotate/v1/tinkrotate.proto\x12\x14lstoll.tinkrotate.v1\x1a\x1egoogle/protobuf/duration.proto\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\x1dgoogle/crypto/tink/tink.proto\"\xf8\x02\n" +
	"\x0eRotationPolicy\x12B\n" +
	"\fkey_template\x18\x01 \x01(\v2\x1f.google.crypto.tink.KeyTemplateR\vkeyTemplate\x12D\n" +
	"\x10primary_duration\x18\x02 \x01(\v2\x19.google.protobuf.DurationR\x0fprimaryDuration\x12D\n" +
	"\x10propagation_time\x18\x03 \x01(\v2\x19.google.protobuf.DurationR\x0fpropagationTime\x12G\n" +
	"\x12phase_out_duration\x18\x04 \x01(\v2\x19.google.protobuf.DurationR\x10phaseOutDuration\x12M\n" +
	"\x15deletion_grace_period\x18\x05 \x01(\v2\x19.google.protobuf.DurationR\x13deletionGracePeriod\"\xde\x02\n" +
	"\vKeyMetadata\x12\x15\n" +
	"\x06key_id\x18\x01 \x01(\rR\x05keyId\x124\n" +
	"\x05state\x18\x02 \x01(\x0e2\x1e.lstoll.tinkrotate.v1.KeyStateR\x05state\x12?\n" +
	"\rcreation_time\x18\x03 \x01(\v2\x1a.google.protobuf.TimestampR\fcreationTime\x12A\n" +
	"\x0epromotion_time\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampR\rpromotionTime\x12=\n" +
	"\fdisable_time\x18\x05 \x01(\v2\x1a.google.protobuf.TimestampR\vdisableTime\x12?\n" +
	"\rdeletion_time\x18\x06 \x01(\v2\x1a.google.protobuf.TimestampR\fdeletionTime\"\xa6\x02\n" +
	"\x13KeyRotationMetadata\x12M\n" +
	"\x0frotation_policy\x18\x01 \x01(\v2$.lstoll.tinkrotate.v1.RotationPolicyR\x0erotationPolicy\x12]\n" +
	"\fkey_metadata\x18\x02 \x03(\v2:.lstoll.tinkrotate.v1.KeyRotationMetadata.KeyMetadataEntryR\vkeyMetadata\x1aa\n" +
	"\x10KeyMetadataEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\rR\x03key\x127\n" +
	"\x05value\x18\x02 \x01(\v2!.lstoll.tinkrotate.v1.KeyMetadataR\x05value:\x028\x01*\x86\x01\n" +
	"\bKeyState\x12\x19\n" +
	"\x15KEY_STATE_UNSPECIFIED\x10\x00\x12\x15\n" +
	"\x11KEY_STATE_PENDING\x10\x01\x12\x15\n" +
	"\x11KEY_STATE_PRIMARY\x10\x02\x12\x19\n" +
	"\x15KEY_STATE_PHASING_OUT\x10\x03\x12\x16\n" +
	"\x12KEY_STATE_DISABLED\x10\x04B?Z=github.com/lstoll/tinkrotate/proto/tinkrotate/v1;tinkrotatev1b\x06proto3"

var (
	file_tinkrotate_v1_tinkrotate_proto_rawDescOnce sync.Once
	file_tinkrotate_v1_tinkrotate_proto_rawDescData []byte
)

func file_tinkrotate_v1_tinkrotate_proto_rawDescGZIP() []byte {
	file_tinkrotate_v1_tinkrotate_proto_rawDescOnce.Do(func() {
		file_tinkrotate_v1_tinkrotate_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_tinkrotate_v1_tinkrotate_proto_rawDesc), len(file_tinkrotate_v1_tinkrotate_proto_rawDesc)))
	})
	return file_tinkrotate_v1_tinkrotate_proto_rawDescData
}

var file_tinkrotate_v1_tinkrotate_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_tinkrotate_v1_tinkrotate_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_tinkrotate_v1_tinkrotate_proto_goTypes = []any{
	(KeyState)(0),                     // 0: lstoll.tinkrotate.v1.KeyState
	(*RotationPolicy)(nil),            // 1: lstoll.tinkrotate.v1.RotationPolicy
	(*KeyMetadata)(nil),               // 2: lstoll.tinkrotate.v1.KeyMetadata
	(*KeyRotationMetadata)(nil),       // 3: lstoll.tinkrotate.v1.KeyRotationMetadata
	nil,                               // 4: lstoll.tinkrotate.v1.KeyRotationMetadata.KeyMetadataEntry
	(*tink_go_proto.KeyTemplate)(nil), // 5: google.crypto.tink.KeyTemplate
	(*durationpb.Duration)(nil),       // 6: google.protobuf.Duration
	(*timestamppb.Timestamp)(nil),     // 7: google.protobuf.Timestamp
}
var file_tinkrotate_v1_tinkrotate_proto_depIdxs = []int32{
	5,  // 0: lstoll.tinkrotate.v1.RotationPolicy.key_template:type_name -> google.crypto.tink.KeyTemplate
	6,  // 1: lstoll.tinkrotate.v1.RotationPolicy.primary_duration:type_name -> google.protobuf.Duration
	6,  // 2: lstoll.tinkrotate.v1.RotationPolicy.propagation_time:type_name -> google.protobuf.Duration
	6,  // 3: lstoll.tinkrotate.v1.RotationPolicy.phase_out_duration:type_name -> google.protobuf.Duration
	6,  // 4: lstoll.tinkrotate.v1.RotationPolicy.deletion_grace_period:type_name -> google.protobuf.Duration
	0,  // 5: lstoll.tinkrotate.v1.KeyMetadata.state:type_name -> lstoll.tinkrotate.v1.KeyState
	7,  // 6: lstoll.tinkrotate.v1.KeyMetadata.creation_time:type_name -> google.protobuf.Timestamp
	7,  // 7: lstoll.tinkrotate.v1.KeyMetadata.promotion_time:type_name -> google.protobuf.Timestamp
	7,  // 8: lstoll.tinkrotate.v1.KeyMetadata.disable_time:type_name -> google.protobuf.Timestamp
	7,  // 9: lstoll.tinkrotate.v1.KeyMetadata.deletion_time:type_name -> google.protobuf.Timestamp
	1,  // 10: lstoll.tinkrotate.v1.KeyRotationMetadata.rotation_policy:type_name -> lstoll.tinkrotate.v1.RotationPolicy
	4,  // 11: lstoll.tinkrotate.v1.KeyRotationMetadata.key_metadata:type_name -> lstoll.tinkrotate.v1.KeyRotationMetadata.KeyMetadataEntry
	2,  // 12: lstoll.tinkrotate.v1.KeyRotationMetadata.KeyMetadataEntry.value:type_name -> lstoll.tinkrotate.v1.KeyMetadata
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_tinkrotate_v1_tinkrotate_proto_init() }
func file_tinkrotate_v1_tinkrotate_proto_init() {
	if File_tinkrotate_v1_tinkrotate_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_tinkrotate_v1_tinkrotate_proto_rawDesc), len(file_tinkrotate_v1_tinkrotate_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_tinkrotate_v1_tinkrotate_proto_goTypes,
		DependencyIndexes: file_tinkrotate_v1_tinkrotate_proto_depIdxs,
		EnumInfos:         file_tinkrotate_v1_tinkrotate_proto_enumTypes,
		MessageInfos:      file_tinkrotate_v1_tinkrotate_proto_msgTypes,
	}.Build()
	File_tinkrotate_v1_tinkrotate_proto = out.File
	file_tinkrotate_v1_tinkrotate_proto_goTypes = nil
	file_tinkrotate_v1_tinkrotate_proto_depIdxs = nil
}
