package com.photon.client.controllers;

import com.photon.client.services.OtaUpdateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/update")
@Slf4j
@RequiredArgsConstructor
public class UpdateController {

    private final OtaUpdateService otaUpdateService;

    /**
     * Endpoint to request an OTA update.
     * This initiates the update flow by sending a request to the server.
     *
     * @param requestedVersion the version to update to
     * @return response with status information
     */
    @PostMapping("/request")
    public ResponseEntity<Map<String, Object>> requestUpdate(@RequestParam String requestedVersion) {
        log.info("Received update request for version: {}", requestedVersion);

        Map<String, Object> response = new HashMap<>();

        if (otaUpdateService.isUpdateInProgress()) {
            log.warn("Update already in progress, cannot start a new one");
            response.put("success", false);
            response.put("message", "Update already in progress");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            otaUpdateService.requestUpdate(requestedVersion);

            response.put("success", true);
            response.put("message", "Update request initiated");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error requesting update", e);
            response.put("success", false);
            response.put("message", "Error requesting update: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * Endpoint to check the status of an ongoing update.
     *
     * @return status information about the update
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getUpdateStatus() {
        Map<String, Object> status = new HashMap<>();

        boolean inProgress = otaUpdateService.isUpdateInProgress();
        status.put("updateInProgress", inProgress);

        if (inProgress) {
            int received = otaUpdateService.getReceivedChunks();
            int total = otaUpdateService.getTotalChunks();
            status.put("receivedChunks", received);
            status.put("totalChunks", total);
            status.put("filename", otaUpdateService.getUpdateFilename());

            if (total > 0) {
                double progress = (double) received / total * 100.0;
                status.put("progress", String.format("%.2f", progress) + "%");
            } else {
                status.put("progress", "0%");
            }
        }

        return ResponseEntity.ok(status);
    }
}