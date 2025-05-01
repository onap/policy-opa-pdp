package publisher

import (
	"encoding/json"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"policy-opa-pdp/cfg"
	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/opasdk"
)

type RealPatchSender struct {
	Producer kafkacomm.KafkaProducerInterface
}

type PatchKafkaPayload struct {
	PatchInfos []opasdk.PatchImpl `json:"patchInfos"`
}

func (s *RealPatchSender) SendPatchMessage(patchInfos []opasdk.PatchImpl) error {
	log.Debugf("In SendPatchMessage")
	var topic string
	topic = cfg.PatchTopic
	kafkaPayload := PatchKafkaPayload{
		PatchInfos: patchInfos,
	}

	jsonMessage, err := json.Marshal(kafkaPayload)
	if err != nil {
		log.Warnf("failed to marshal Patch Payload to JSON: %v", err)
		return err
	}

	kafkaMessage := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &topic,
			Partition: kafka.PartitionAny,
		},
		Value: jsonMessage,
	}
	var eventChan chan kafka.Event = nil
	err = s.Producer.Produce(kafkaMessage, eventChan)
	if err != nil {
		log.Warnf("Error producing message: %v\n", err)
		return err
	} else {
		log.Debugf("[OUT|KAFKA|%s]\n%s", topic, string(jsonMessage))
	}

	return nil
}
