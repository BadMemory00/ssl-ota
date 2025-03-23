package com.photon.server.listeners;

import com.photon.server.services.OtaUpdateService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class MqttListener implements MqttCallback {

    @Value("${mqtt.request.topic}")
    private String requestTopic;

    private final MqttClient mqttClient;
    private final OtaUpdateService otaUpdateService;

    public MqttListener(MqttClient mqttClient, OtaUpdateService otaUpdateService) {
        this.mqttClient = mqttClient;
        this.otaUpdateService = otaUpdateService;
    }

    @PostConstruct
    public void init() {
        try {
            // Set callback
            mqttClient.setCallback(this);

            // Subscribe to topic
            if (mqttClient.isConnected()) {
                mqttClient.subscribe(requestTopic, 1);
                log.info("Successfully subscribed to topic: {}", requestTopic);
            } else {
                log.error("Cannot subscribe to topic - MQTT client is not connected");
            }
        } catch (MqttException e) {
            log.error("Error initializing MQTT listener: {}", e.getMessage(), e);
        }
    }

    @Override
    public void connectionLost(Throwable cause) {
        log.error("Connection to MQTT broker lost: {}", cause.getMessage());

        // Try to reconnect
        try {
            log.info("Attempting to reconnect to MQTT broker...");
            mqttClient.reconnect();

            // Resubscribe
            mqttClient.subscribe(requestTopic, 1);
            log.info("Reconnected and resubscribed to topic: {}", requestTopic);
        } catch (MqttException e) {
            log.error("Failed to reconnect to MQTT broker: {}", e.getMessage());
        }
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) throws Exception {
        try {
            log.info("Received message on topic: {}", topic);

            if (requestTopic.equals(topic)) {
                String payload = new String(message.getPayload());
                log.info("Message payload: {}", payload);
                otaUpdateService.processUpdateRequest(payload);
            }
        } catch (Exception e) {
            log.error("Error processing message: {}", e.getMessage(), e);
        }
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
        try {
            log.debug("Message delivery complete: {}", token.getMessage());
        } catch (MqttException e) {
            log.error("Error in deliveryComplete: {}", e.getMessage());
        }
    }
}