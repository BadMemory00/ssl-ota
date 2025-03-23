package com.photon.client.listeners;

import com.photon.client.services.OtaUpdateService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class MqttListener implements MqttCallback {

    @Value("${mqtt.updates.topic}")
    private String updatesTopic;

    // If you also need the requestTopic for any reason, you can add:
    // @Value("${mqtt.request.topic}")
    // private String requestTopic;

    private final MqttClient mqttClient;
    private final OtaUpdateService otaUpdateService;

    public MqttListener(MqttClient mqttClient, OtaUpdateService otaUpdateService) {
        this.mqttClient = mqttClient;
        this.otaUpdateService = otaUpdateService;
    }

    /**
     * Set ourselves as callback and subscribe after the bean is constructed.
     */
    @PostConstruct
    public void init() throws MqttException {
        mqttClient.setCallback(this);
        subscribeToUpdatesTopic();
    }

    private void subscribeToUpdatesTopic() throws MqttException {
        // QoS 2 - Exactly once
        mqttClient.subscribe(updatesTopic, 2);
        log.info("Subscribed to topic: {}", updatesTopic);
    }

    @Override
    public void connectionLost(Throwable cause) {
        log.error("Connection to MQTT broker lost", cause);
        // Optionally, attempt reconnection here if desired. For example:
        /*
        try {
            log.info("Attempting to reconnect to MQTT broker...");
            mqttClient.reconnect();
            subscribeToUpdatesTopic();
            log.info("Reconnected to MQTT broker");
        } catch (MqttException e) {
            log.error("Failed to reconnect to MQTT broker", e);
        }
        */
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) throws Exception {
        log.info("Received message on topic: {}", topic);

        // If the message is on the updates topic, forward it to OtaUpdateService
        if (updatesTopic.equals(topic)) {
            otaUpdateService.processUpdateChunk(message.toString());
        }
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
        log.debug("Message delivery complete: {}", token.getMessageId());
    }
}
