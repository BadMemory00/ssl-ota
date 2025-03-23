package com.photon.client.services;

import com.photon.client.models.UpdateChunk;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@Slf4j
public class OtaUpdateService {

    @Value("${client.device.id}")
    private String deviceId;

    @Value("${client.firmware.version}")
    private String currentVersion;

    @Value("${client.firmware.output-dir}")
    private String outputDir;

    @Value("${mqtt.request.topic}")
    private String requestTopic; // Now we inject this directly instead of calling mqttConfig.getRequestTopic()

    private final MqttClient mqttClient;
    private final ObjectMapper objectMapper;

    private final AtomicBoolean updateInProgress = new AtomicBoolean(false);
    private final AtomicInteger receivedChunks = new AtomicInteger(0);

    @Getter
    private int totalChunks = 0;

    @Getter
    private String updateFilename = null;

    // Store chunks until all are received
    private final Map<Integer, byte[]> chunkData = new ConcurrentHashMap<>();
    private final Map<Integer, String> chunkChecksums = new ConcurrentHashMap<>();

    /**
     * We inject the MqttClient bean directly (instead of MqttConfig).
     */
    @Autowired
    public OtaUpdateService(MqttClient mqttClient, ObjectMapper objectMapper) {
        this.mqttClient = mqttClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Sends an OTA update request to the server.
     */
    public void requestUpdate(String requestedVersion) {
        if (updateInProgress.get()) {
            log.warn("Update already in progress. Cannot request a new update.");
            return;
        }

        try {
            log.info("Requesting OTA update from version {} to {}", currentVersion, requestedVersion);

            // Create update request
            UpdateChunk request = new UpdateChunk();
            request.setRequest(true);
            request.setDeviceId(deviceId);
            request.setCurrentVersion(currentVersion);
            request.setRequestedVersion(requestedVersion);

            // Convert request to JSON
            String requestJson = objectMapper.writeValueAsString(request);

            // Publish request to the "request topic"
            MqttMessage message = new MqttMessage(requestJson.getBytes());
            message.setQos(2); // Exactly once
            mqttClient.publish(requestTopic, message);

            log.info("Update request sent to server on topic: {}", requestTopic);

            // Mark update as in progress
            updateInProgress.set(true);

            // Reset counters and collections
            receivedChunks.set(0);
            totalChunks = 0;
            updateFilename = null;
            chunkData.clear();
            chunkChecksums.clear();

        } catch (Exception e) {
            log.error("Error requesting update", e);
            updateInProgress.set(false);
        }
    }

    /**
     * Processes an incoming update chunk from the server.
     */
    public void processUpdateChunk(String chunkJson) {
        try {
            // Parse the chunk
            UpdateChunk chunk = objectMapper.readValue(chunkJson, UpdateChunk.class);

            // Get chunk metadata
            int chunkNumber = chunk.getChunkNumber();
            int totalChunks = chunk.getTotalChunks();
            String filename = chunk.getFilename();
            byte[] data = chunk.getData();
            String checksum = chunk.getChecksum();

            // Set overall metadata if this is the first chunk
            if (this.totalChunks == 0) {
                this.totalChunks = totalChunks;
                this.updateFilename = filename;
                log.info("Starting firmware update for file: {}, total chunks: {}", filename, totalChunks);
            }

            // Verify the checksum
            String calculatedChecksum = calculateSHA256(data);
            if (!calculatedChecksum.equals(checksum)) {
                log.error("Checksum verification failed for chunk {}/{}. Expected: {}, Calculated: {}",
                        chunkNumber + 1, totalChunks, checksum, calculatedChecksum);
                return;
            }

            log.info("Received and verified chunk {}/{} for file: {}, size: {} bytes",
                    chunkNumber + 1, totalChunks, filename, data.length);

            // Store the chunk data and checksum
            chunkData.put(chunkNumber, data);
            chunkChecksums.put(chunkNumber, checksum);

            // Increment received chunks counter
            int received = receivedChunks.incrementAndGet();

            // Log progress
            double progress = (double) received / totalChunks * 100.0;
            log.info("Update progress: {}% ({}/{})",
                    String.format("%.2f", progress), received, totalChunks);

            // If this was the last chunk or we've received them all, assemble the file
            if (chunk.isLast() || received == totalChunks) {
                assembleFile();
            }

        } catch (Exception e) {
            log.error("Error processing update chunk", e);
        }
    }

    /**
     * Once we've received all chunks, reconstruct the file.
     */
    private void assembleFile() {
        try {
            log.info("All chunks received. Assembling file: {}", updateFilename);

            // Ensure output directory exists
            Files.createDirectories(Paths.get(outputDir));

            // Build the path
            String outputPath = outputDir + File.separator + updateFilename;
            File outputFile = new File(outputPath);

            // Write each chunk in order
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                for (int i = 0; i < totalChunks; i++) {
                    byte[] data = chunkData.get(i);
                    if (data == null) {
                        log.error("Missing chunk {} for file: {}", i, updateFilename);
                        updateInProgress.set(false);
                        return;
                    }
                    fos.write(data);
                }
                fos.flush();
            }

            log.info("File assembled successfully: {}", outputPath);
            log.info("Firmware update complete. New file available at: {}", outputPath);

            // Reset update state
            updateInProgress.set(false);

        } catch (Exception e) {
            log.error("Error assembling file", e);
            updateInProgress.set(false);
        }
    }

    /**
     * Helper method to calculate SHA-256.
     */
    private String calculateSHA256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

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

    public boolean isUpdateInProgress() {
        return updateInProgress.get();
    }

    public int getReceivedChunks() {
        return receivedChunks.get();
    }
}
