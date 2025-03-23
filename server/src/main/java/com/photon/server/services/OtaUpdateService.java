package com.photon.server.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.photon.server.models.UpdateChunk;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;

/**
 * Handles all OTA update requests received from devices.
 */
@Service
@Slf4j
public class OtaUpdateService {

    private static final int CHUNK_SIZE = 4 * 1024; // 4KB

    @Value("${ota.firmware.path}")
    private String firmwarePath;

    @Value("${mqtt.updates.topic}")
    private String updatesTopic;

    private final MqttClient mqttClient;
    private final ObjectMapper objectMapper;

    public OtaUpdateService(MqttClient mqttClient, ObjectMapper objectMapper) {
        this.mqttClient = mqttClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Processes an incoming JSON request for a firmware update.
     */
    @Async
    public void processUpdateRequest(String requestJson) {
        try {
            log.info("Processing update request: {}", requestJson);
            UpdateChunk request = objectMapper.readValue(requestJson, UpdateChunk.class);

            // If it's a request (i.e., device wants an update) then send out the firmware in chunks.
            if (request.isRequest()) {
                log.info("Received OTA update request from device: {}, current version: {}, requested version: {}",
                        request.getDeviceId(), request.getCurrentVersion(), request.getRequestedVersion());

                File firmwareFile = new File(firmwarePath);
                if (!firmwareFile.exists()) {
                    log.error("Firmware file not found: {}", firmwarePath);
                    return;
                }

                log.info("Starting firmware update process for file: {}, size: {} bytes",
                        firmwareFile.getName(), firmwareFile.length());

                // Read the entire firmware file
                byte[] firmwareBytes = Files.readAllBytes(firmwareFile.toPath());
                int totalChunks = (int) Math.ceil((double) firmwareBytes.length / CHUNK_SIZE);
                log.info("Firmware split into {} chunks of {} bytes each", totalChunks, CHUNK_SIZE);

                // Send chunks
                sendFirmwareChunks(firmwareFile.getName(), firmwareBytes, totalChunks);
            }
        } catch (Exception e) {
            log.error("Error processing update request", e);
        }
    }

    /**
     * Splits the firmware into chunks and publishes them via MQTT.
     */
    private void sendFirmwareChunks(String filename, byte[] firmwareBytes, int totalChunks) throws Exception {
        for (int i = 0; i < totalChunks; i++) {
            // Calculate start/end for the chunk
            int start = i * CHUNK_SIZE;
            int end = Math.min((i + 1) * CHUNK_SIZE, firmwareBytes.length);

            byte[] chunkData = new byte[end - start];
            System.arraycopy(firmwareBytes, start, chunkData, 0, end - start);

            // Calculate checksum
            String checksum = calculateSHA256(chunkData);

            // Create the chunk metadata
            UpdateChunk chunk = new UpdateChunk();
            chunk.setChunkNumber(i);
            chunk.setTotalChunks(totalChunks);
            chunk.setFilename(filename);
            chunk.setData(chunkData);
            chunk.setChecksum(checksum);
            chunk.setLast(i == totalChunks - 1);
            chunk.setRequest(false); // Because we're sending actual chunk data now

            // Serialize to JSON
            String chunkJson = objectMapper.writeValueAsString(chunk);

            // Publish via MQTT (QoS 2)
            MqttMessage mqttMessage = new MqttMessage(chunkJson.getBytes());
            mqttMessage.setQos(2);
            mqttClient.publish(updatesTopic, mqttMessage);

            log.info("Sent chunk {}/{} for file: {}, size: {} bytes",
                    (i + 1), totalChunks, filename, chunkData.length);

            // Short delay to avoid overwhelming the device
            Thread.sleep(100);
        }

        log.info("Firmware update transmission complete for file: {}", filename);
    }

    /**
     * Calculates the SHA-256 checksum for a given byte array.
     */
    private String calculateSHA256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        // Convert hash to hex
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
