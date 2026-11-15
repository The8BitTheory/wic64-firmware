#include "wic64.h"
#include "tcpClient.h"
#include "lwip/sockets.h"
#include "esp_crt_bundle.h"
#include "esp_tls_errors.h"
#include "esp_timer.h"

namespace WiC64 {
    const char* TcpClient::TAG = "TCPCLIENT";
    static bool waitForSocket(int fd, bool write, int timeoutMs) {
        if (fd < 0) return false;
        fd_set set; FD_ZERO(&set); FD_SET(fd, &set);
        struct timeval timeout;
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;
        return select(fd + 1, write ? NULL : &set, write ? &set : NULL, NULL, &timeout) > 0;
    }
    TcpClient::TcpClient() {
        m_unconfirmed = (uint8_t*) malloc(MAX_READ_CHUNK_SIZE);
        ESP_LOGI(TAG, "TCP client initialized");
    }
    int TcpClient::socketFd(void) const {
        if (m_tls != nullptr) {
            int fd = -1;
            return esp_tls_get_conn_sockfd(m_tls, &fd) == ESP_OK ? fd : -1;
        }
        return m_client.fd();
    }
    bool TcpClient::connected(void) {
        if (m_unconfirmed_size > 0) return true;
        if (m_tls != nullptr && m_tls_closed) return false;
        if (m_tls == nullptr && !m_client.connected()) return false;
        if (available() > 0) return true;
        int fd = socketFd();
        if (fd < 0) return false;
        uint8_t byte;
        int result = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
        if (result == 0 || (result < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) {
            ESP_LOGI(TAG, "Connection closed by the server");
            return false;
        }
        return true;
    }
    int TcpClient::open(const char* host, const uint16_t port, bool useTls) {
        m_unconfirmed_size = 0;
        close();
        m_tls_closed = false;
        bool connected = false;
        if (useTls) {
            m_tls = esp_tls_init();
            if (m_tls == nullptr) {
                ESP_LOGE(TAG, "Could not allocate TLS context");
                return 0;
            }
            esp_tls_cfg_t cfg = {};
            cfg.timeout_ms = 5000;
            cfg.crt_bundle_attach = esp_crt_bundle_attach;
            int result = esp_tls_conn_new_sync(host, strlen(host), port, &cfg, m_tls);
            connected = result == 1;
            if (!connected) {
                ESP_LOGE(TAG, "TLS handshake failed for %s:%u (result %d)", host, port, result);
                esp_tls_conn_destroy(m_tls);
                m_tls = nullptr;
            }
        } else {
            connected = m_client.connect(host, port, 5000);
        }
        ESP_LOG_LEVEL((connected ? ESP_LOG_INFO : ESP_LOG_ERROR), TAG,
            "%s %s connection to %s on port %d",
            connected ? "Opened" : "Failed to open", useTls ? "TLS" : "TCP", host, port);
        return connected;
    }
    int32_t TcpClient::available(void) {
        if (m_tls == nullptr) return m_unconfirmed_size + m_client.available();
        int32_t pending = (int32_t) esp_tls_get_bytes_avail(m_tls);
        int fd = socketFd();
        if (pending <= 0 && fd >= 0) {
            fd_set set; FD_ZERO(&set); FD_SET(fd, &set);
            struct timeval timeout = { 0, 0 };
            if (select(fd + 1, &set, NULL, NULL, &timeout) > 0) pending = 1;
        }
        return m_unconfirmed_size + (pending > 0 ? pending : 0);
    }
    int64_t TcpClient::read(uint8_t* data) {
        if (m_unconfirmed_size > 0) {
            ESP_LOGW(TAG, "Sending the %d bytes of the last read again", m_unconfirmed_size);
            memcpy(data, m_unconfirmed, m_unconfirmed_size);
            return m_unconfirmed_size;
        }
        int64_t bytesRead = -1;
        if (available() > 0) {
            if (m_tls == nullptr) {
                bytesRead = m_client.read(data, MAX_READ_CHUNK_SIZE);
            } else {
                int fd = socketFd();
                int64_t start = esp_timer_get_time();
                do {
                    bytesRead = esp_tls_conn_read(m_tls, data, MAX_READ_CHUNK_SIZE);
                    if (bytesRead == ESP_TLS_ERR_SSL_WANT_READ) {
                        if (!waitForSocket(fd, false, 5000)) break;
                    } else if (bytesRead == ESP_TLS_ERR_SSL_WANT_WRITE) {
                        if (!waitForSocket(fd, true, 5000)) break;
                    } else break;
                } while (esp_timer_get_time() - start < 5000000);
            }
            ESP_LOGI(TAG, "Read %lld bytes", bytesRead);
            if (m_tls != nullptr && (bytesRead == 0 || (bytesRead < 0 && bytesRead != ESP_TLS_ERR_SSL_WANT_READ && bytesRead != ESP_TLS_ERR_SSL_WANT_WRITE))) {
                m_tls_closed = true;
            }
            if (bytesRead > 0) {
                memcpy(m_unconfirmed, data, bytesRead);
                m_unconfirmed_size = bytesRead;
            }
        }
        return bytesRead;
    }
    void TcpClient::confirmRead(void) { m_unconfirmed_size = 0; }
    int32_t TcpClient::write(Data *data) { return write(data->data(), data->size()); }
    int32_t TcpClient::write(uint8_t *data, uint32_t size) {
        ESP_LOGI(TAG, "Writing %d bytes", size);
        int32_t written = 0;
        if (m_tls == nullptr) written = m_client.write(data, size);
        else {
            int fd = socketFd();
            int64_t start = esp_timer_get_time();
            while ((uint32_t) written < size && esp_timer_get_time() - start < 5000000) {
                int result = esp_tls_conn_write(m_tls, data + written, size - written);
                if (result > 0) written += result;
                else if (result == ESP_TLS_ERR_SSL_WANT_READ) {
                    if (!waitForSocket(fd, false, 5000)) break;
                } else if (result == ESP_TLS_ERR_SSL_WANT_WRITE) {
                    if (!waitForSocket(fd, true, 5000)) break;
                } else {
                    m_tls_closed = true;
                    break;
                }
            }
        }
        if ((uint32_t) written < size) {
            if (written <= 0) ESP_LOGE(TAG, "Failed to write any data");
            else ESP_LOGE(TAG, "Wrote only %d of %d bytes", written, size);
        } else ESP_LOGI(TAG, "Wrote %d bytes", written);
        return written;
    }
    void TcpClient::close(void) {
        ESP_LOGI(TAG, "Closing connection");
        m_unconfirmed_size = 0;
        if (m_tls != nullptr) {
            esp_tls_conn_destroy(m_tls);
            m_tls = nullptr;
        }
        m_client.stop();
    }
}
