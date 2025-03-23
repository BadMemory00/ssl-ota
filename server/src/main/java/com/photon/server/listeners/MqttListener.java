package com.photon.server.listeners;

import com.photon.server.services.OtaUpdateService;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

@Service
@Slf4j
public class MqttListener implements MqttCallback {

    @Value("${mqtt.request.topic}")
    private String requestTopic;

    private final MqttClient mqttClient;
    private final OtaUpdateService otaUpdateService;

    /**
     * The constructor injects both the MqttClient and OtaUpdateService.
     */
    public MqttListener(MqttClient mqttClient, OtaUpdateService otaUpdateService) {
        this.mqttClient = mqttClient;
        this.otaUpdateService = otaUpdateService;
    }

    /**
     * Once Spring has constructed this bean, we set ourselves as the callback,
     * and subscribe to the relevant topic(s).
     */
    @PostConstruct
    public void init() throws MqttException {
        // Set this service as the callback
        mqttClient.setCallback(this);

        // Subscribe to the request topic
        mqttClient.subscribe(requestTopic, 2);
        log.info("Subscribed to topic: {}", requestTopic);
    }

    @Override
    public void connectionLost(Throwable cause) {
        log.error("Connection to MQTT broker lost", cause);
        // You could add reconnection logic here if desired.
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) throws Exception {
        log.info("Received message on topic: {}", topic);
        if (requestTopic.equals(topic)) {
            // Hand the request to OtaUpdateService
            otaUpdateService.processUpdateRequest(message.toString());
        }
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
        log.debug("Message delivery complete: {}", token.getMessageId());
    }
}
