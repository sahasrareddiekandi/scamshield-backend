package com.scamshield.dto;

import java.util.List;

public class UrlDetailsDto {
    private String normalizedUrl;
    private String protocol;
    private String host;
    private int port;
    private String path;
    private String query;
    private boolean isHttps;
    private boolean isIpAddress;
    private int urlLength;
    private boolean hasSuspiciousTld;
    private List<String> detectedKeywords;
    private boolean hasSpecialCharacters;
    private int subdomainCount;

    public UrlDetailsDto() {}

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public void setNormalizedUrl(String normalizedUrl) {
        this.normalizedUrl = normalizedUrl;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public boolean isHttps() {
        return isHttps;
    }

    public void setHttps(boolean https) {
        isHttps = https;
    }

    public boolean isIpAddress() {
        return isIpAddress;
    }

    public void setIpAddress(boolean ipAddress) {
        isIpAddress = ipAddress;
    }

    public int getUrlLength() {
        return urlLength;
    }

    public void setUrlLength(int urlLength) {
        this.urlLength = urlLength;
    }

    public boolean isHasSuspiciousTld() {
        return hasSuspiciousTld;
    }

    public void setHasSuspiciousTld(boolean hasSuspiciousTld) {
        this.hasSuspiciousTld = hasSuspiciousTld;
    }

    public List<String> getDetectedKeywords() {
        return detectedKeywords;
    }

    public void setDetectedKeywords(List<String> detectedKeywords) {
        this.detectedKeywords = detectedKeywords;
    }

    public boolean isHasSpecialCharacters() {
        return hasSpecialCharacters;
    }

    public void setHasSpecialCharacters(boolean hasSpecialCharacters) {
        this.hasSpecialCharacters = hasSpecialCharacters;
    }

    public int getSubdomainCount() {
        return subdomainCount;
    }

    public void setSubdomainCount(int subdomainCount) {
        this.subdomainCount = subdomainCount;
    }
}
