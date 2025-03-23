package com.photon.client.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateChunk {

    private static final long serialVersionUID = 1L;

    private int chunkNumber;
    private int totalChunks;
    private String filename;
    private byte[] data;
    private String checksum;
    private boolean isLast;

    // Used for initial update request from client to server
    private boolean isRequest;
    private String deviceId;
    private String currentVersion;
    private String requestedVersion;
}
