#define _POSIX_C_SOURCE 200809L

#include "protocol.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int gyrojet_protocol_send_all(
    gyrojet_connection_t *connection,
    const void *buffer,
    size_t size
)
{
    if (connection == NULL ||
        buffer == NULL ||
        connection->fd < 0) {

        return -1;
    }

    if (gyrojet_connection_send(
            connection,
            buffer,
            size
        ) < 0) {

        return -1;
    }

    return 0;
}

static int gyrojet_protocol_recv_all(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
)
{
    if (connection == NULL ||
        buffer == NULL ||
        connection->fd < 0) {

        return -1;
    }

    unsigned char *ptr = buffer;
    size_t received = 0;

    while (received < size) {
        ssize_t result = gyrojet_connection_recv(
            connection,
            ptr + received,
            size - received
        );

        if (result < 0)
            return -1;

        if (result == 0)
            return 1;

        received += (size_t)result;
    }

    return 0;
}

static int gyrojet_protocol_build_aad(
    const unsigned char header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ],
    const unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ],
    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ]
)
{
    if (header == NULL ||
        nonce == NULL ||
        aad == NULL) {

        return -1;
    }

    memcpy(
        aad,
        header,
        GYROJET_PROTOCOL_HEADER_SIZE
    );

    memcpy(
        aad + GYROJET_PROTOCOL_HEADER_SIZE,
        nonce,
        GYROJET_PROTOCOL_NONCE_SIZE
    );

    return 0;
}

int gyrojet_protocol_init(
    gyrojet_protocol_t *protocol,
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
)
{
    if (protocol == NULL ||
        connection == NULL ||
        key == NULL ||
        connection->fd < 0) {

        return -1;
    }

    memset(
        protocol,
        0,
        sizeof(*protocol)
    );

    protocol->connection = connection;

    memcpy(
        protocol->key,
        key,
        sizeof(protocol->key)
    );

    protocol->send_sequence = 0;
    protocol->receive_sequence = 0;

    return 0;
}

int gyrojet_protocol_send(
    gyrojet_protocol_t *protocol,
    uint8_t type,
    const unsigned char *payload,
    size_t payload_size
)
{
    if (protocol == NULL ||
        protocol->connection == NULL) {

        return -1;
    }

    if (payload == NULL &&
        payload_size != 0) {

        return -1;
    }

    if (payload_size >
        GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {

        return -1;
    }

    if (payload_size > UINT32_MAX)
        return -1;

    gyrojet_frame_header_t frame_header = {
        .version = GYROJET_PROTOCOL_VERSION,
        .type = type,
        .flags = 0,
        .sequence = protocol->send_sequence,
        .payload_size = (uint32_t)payload_size
    };

    unsigned char header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ];

    unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char tag[
        GYROJET_PROTOCOL_TAG_SIZE
    ];

    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char *ciphertext = NULL;

    int result = -1;

    if (gyrojet_frame_header_encode(
            &frame_header,
            header
        ) < 0) {

        goto cleanup;
    }

    if (gyrojet_crypto_random(
            nonce,
            sizeof(nonce)
        ) < 0) {

        goto cleanup;
    }

    if (gyrojet_protocol_build_aad(
            header,
            nonce,
            aad
        ) < 0) {

        goto cleanup;
    }

    if (payload_size > 0) {
        ciphertext = malloc(payload_size);

        if (ciphertext == NULL)
            goto cleanup;
    }

    if (gyrojet_aead_encrypt(
            protocol->key,
            nonce,
            payload,
            payload_size,
            aad,
            sizeof(aad),
            ciphertext,
            tag
        ) < 0) {

        goto cleanup;
    }

    if (gyrojet_protocol_send_all(
            protocol->connection,
            header,
            sizeof(header)
        ) < 0) {

        goto cleanup;
    }

    if (gyrojet_protocol_send_all(
            protocol->connection,
            nonce,
            sizeof(nonce)
        ) < 0) {

        goto cleanup;
    }

    if (payload_size > 0) {
        if (gyrojet_protocol_send_all(
                protocol->connection,
                ciphertext,
                payload_size
            ) < 0) {

            goto cleanup;
        }
    }

    if (gyrojet_protocol_send_all(
            protocol->connection,
            tag,
            sizeof(tag)
        ) < 0) {

        goto cleanup;
    }

    /*
     * Só incrementamos a sequência depois que
     * o frame inteiro foi transmitido.
     */
    protocol->send_sequence++;

    result = 0;

cleanup:

    if (ciphertext != NULL) {
        gyrojet_crypto_secure_zero(
            ciphertext,
            payload_size
        );

        free(ciphertext);
    }

    gyrojet_crypto_secure_zero(
        nonce,
        sizeof(nonce)
    );

    gyrojet_crypto_secure_zero(
        tag,
        sizeof(tag)
    );

    gyrojet_crypto_secure_zero(
        aad,
        sizeof(aad)
    );

    return result;
}

int gyrojet_protocol_receive(
    gyrojet_protocol_t *protocol,
    gyrojet_frame_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_size
)
{
    if (protocol == NULL ||
        protocol->connection == NULL ||
        header == NULL ||
        payload_size == NULL) {

        return -1;
    }

    *payload_size = 0;

    unsigned char raw_header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ];

    unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char tag[
        GYROJET_PROTOCOL_TAG_SIZE
    ];

    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char *ciphertext = NULL;

    int result = -1;

    int recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        raw_header,
        sizeof(raw_header)
    );

    if (recv_result != 0)
        return recv_result;

    if (gyrojet_frame_header_decode(
            raw_header,
            header
        ) < 0) {

        return -1;
    }

    if (header->sequence !=
        protocol->receive_sequence) {

        return -1;
    }

    if ((size_t)header->payload_size >
        payload_capacity) {

        return -1;
    }

    if (header->payload_size > 0 &&
        payload == NULL) {

        return -1;
    }

    recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        nonce,
        sizeof(nonce)
    );

    if (recv_result != 0)
        return recv_result;

    if (header->payload_size > 0) {
        ciphertext = malloc(
            header->payload_size
        );

        if (ciphertext == NULL)
            goto cleanup;

        recv_result = gyrojet_protocol_recv_all(
            protocol->connection,
            ciphertext,
            header->payload_size
        );

        if (recv_result != 0)
            goto cleanup;
    }

    recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        tag,
        sizeof(tag)
    );

    if (recv_result != 0)
        goto cleanup;

    if (gyrojet_protocol_build_aad(
            raw_header,
            nonce,
            aad
        ) < 0) {

        goto cleanup;
    }

    if (gyrojet_aead_decrypt(
            protocol->key,
            nonce,
            ciphertext,
            header->payload_size,
            aad,
            sizeof(aad),
            tag,
            payload
        ) < 0) {

        goto cleanup;
    }

    *payload_size = header->payload_size;

    protocol->receive_sequence++;

    result = 0;

cleanup:

    if (ciphertext != NULL) {
        gyrojet_crypto_secure_zero(
            ciphertext,
            header->payload_size
        );

        free(ciphertext);
    }

    gyrojet_crypto_secure_zero(
        nonce,
        sizeof(nonce)
    );

    gyrojet_crypto_secure_zero(
        tag,
        sizeof(tag)
    );

    gyrojet_crypto_secure_zero(
        aad,
        sizeof(aad)
    );

    return result;
}

void gyrojet_protocol_clear(
    gyrojet_protocol_t *protocol
)
{
    if (protocol == NULL)
        return;

    gyrojet_crypto_secure_zero(
        protocol,
        sizeof(*protocol)
    );
}
